import os
import mmap
import subprocess
import multiprocessing
import time
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from src.patterns import find_secrets_in_file
from src.secret_scanner.logger import logger

def is_text_file(file_path):
    """Check if a file is likely a text file"""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return False
        return True
    except (OSError, IOError):
        # Handle file access errors gracefully
        return False

def get_files_to_scan(directory):
    """Get list of files to scan, preferring git ls-files for faster traversal."""
    dir_path = Path(directory)

    # Try to use git ls-files for faster file listing in git repos
    try:
        result = subprocess.run(['git', 'ls-files'], cwd=directory, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            git_files = [dir_path / f.strip() for f in result.stdout.strip().split('\n') if f.strip()]
            logger.info(f"Using git ls-files: found {len(git_files)} tracked files")
            return git_files
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback to directory traversal
    logger.info("Falling back to directory traversal")
    exclude_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                          '.mp3', '.mp4', '.avi', '.mov', '.zip', '.tar', '.gz',
                          '.exe', '.dll', '.so', '.dylib', '.pyc', '.class'}

    files = []
    for file_path in dir_path.rglob('*'):
        if file_path.is_file() and file_path.suffix.lower() not in exclude_extensions:
            files.append(file_path)

    return files

def scan_single_file(file_path):
    """Scan a single file for secrets (used by multiprocessing workers)."""
    findings = []

    try:
        if not is_text_file(str(file_path)):
            return []

        # Get file size
        file_size = os.path.getsize(file_path)

        # Skip files larger than 100MB to allow larger files for maximum coverage
        if file_size > 100 * 1024 * 1024:
            return []

        # Read file content using mmap for better performance
        try:
            with open(file_path, 'rb') as f:
                # Use mmap for memory-mapped file access
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Decode bytes to string, ignoring encoding errors
                    content = mm.read().decode('utf-8', errors='ignore')
        except (OSError, IOError, UnicodeDecodeError, ValueError) as e:
            # Handle file reading errors, fallback to regular reading
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50 * 1024 * 1024)  # Read up to 50MB per file
            except (OSError, IOError, UnicodeDecodeError) as e:
                return {'error': f'File read error: {str(e)}', 'file': str(file_path)}

        file_findings = find_secrets_in_file(str(file_path), content)
        return file_findings

    except Exception as e:
        # Return error info instead of logging in worker
        return {'error': str(e), 'file': str(file_path)}

def scan_directory(directory):
    """Scan a directory for potential secrets using multiprocessing"""
    logger.info(f"Starting directory scan: {directory}")
    dir_path = Path(directory)

    if not dir_path.exists():
        logger.error(f"Directory '{directory}' does not exist.")
        return []

    logger.info(f"Scanning directory: {directory}")

    # Timing: File discovery
    start_time = time.time()
    files_to_scan = get_files_to_scan(directory)
    file_discovery_time = time.time() - start_time

    total_files = len(files_to_scan)

    if not files_to_scan:
        logger.info("No files to scan")
        return {
                'file_discovery_time': file_discovery_time,
                'scan_time': 0.0,
                'total_files': 0,
                'scanned_files': 0,
                'findings_count': 0
            }

    logger.info(f"Found {total_files} files to scan in {file_discovery_time:.2f}s")

    # Determine number of worker processes (use ALL available CPU cores for maximum speed)
    num_workers = multiprocessing.cpu_count()
    logger.info(f"Using ALL {num_workers} CPU cores for maximum parallel scanning speed")

    scanned_files = 0

    # Timing: Multiprocessing scan
    scan_start_time = time.time()

    # Use ProcessPoolExecutor for multiprocessing
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        logger.info(f"Submitting {len(files_to_scan)} tasks to worker pool...")
        # Submit all tasks
        future_to_file = {executor.submit(scan_single_file, file_path): file_path for file_path in files_to_scan}
        logger.info(f"All {len(future_to_file)} tasks submitted, waiting for completion...")

        # Collect results as they complete
        completed_count = 0
        for future in as_completed(future_to_file):
            completed_count += 1
            file_path = future_to_file[future]
            logger.debug(f"Processing result {completed_count}/{len(future_to_file)} for {file_path}")
            try:
                result = future.result()
                scanned_files += 1

                if isinstance(result, dict) and 'error' in result:
                    # Handle error from worker
                    logger.error(f"Error reading {result['file']}: {result['error']}")
                elif isinstance(result, list):
                    # Normal findings - send to async writer immediately
                    if result:
                        # Group findings by confidence for better logging
                        high_conf = sum(1 for f in result if f.get('confidence') == 'high')
                        medium_conf = sum(1 for f in result if f.get('confidence') == 'medium')
                        low_conf = sum(1 for f in result if f.get('confidence') == 'low')
                        logger.info(f"Found {len(result)} secrets in {file_path} (high:{high_conf}, medium:{medium_conf}, low:{low_conf})")

                    # Send findings to async writer
                    from src.output import findings_queue
                    findings_queue.put({'findings': result})

                # Progress logging every 100 files
                if scanned_files % 100 == 0:
                    logger.info(f"Progress: {scanned_files}/{total_files} files scanned")

            except Exception as e:
                logger.error(f"Error processing {file_path}: {e}")
                scanned_files += 1

        logger.info(f"All {completed_count} tasks completed")

    scan_time = time.time() - scan_start_time
    logger.info(f"Scan complete: {scanned_files}/{total_files} files scanned")

    # Return timing stats only (findings are sent asynchronously)
    return {
        'file_discovery_time': file_discovery_time,
        'scan_time': scan_time,
        'total_files': total_files,
        'scanned_files': scanned_files,
        'findings_count': 0  # Will be calculated by the writer
    }
