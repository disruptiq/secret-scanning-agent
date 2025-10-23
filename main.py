#!/usr/bin/env python3

import sys
import os
import subprocess
import argparse
import logging
import json
import mmap
import multiprocessing
import threading
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from logging.handlers import QueueHandler, QueueListener
from patterns import find_secrets_in_file
from queue import Queue, Empty

# Set up asynchronous logging
log_queue = multiprocessing.Queue()

# Create a console handler for the queue listener
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Create the queue listener
listener = QueueListener(log_queue, console_handler)
listener.start()

# Disable default logging and set up queue-based logging
logging.getLogger().handlers.clear()
logging.getLogger().addHandler(QueueHandler(log_queue))
logging.getLogger().setLevel(logging.INFO)

# Create a logger for this module
logger = logging.getLogger(__name__)

# Set up asynchronous file writing
findings_queue = Queue()
output_file_path = None  # Will be set when scan starts

def async_file_writer():
    """Asynchronous file writer that processes findings from the queue."""
    global output_file_path
    findings_buffer = []
    scan_info = None
    tools_info = {}

    while True:
        try:
            # Get item from queue with timeout
            item = findings_queue.get(timeout=0.1)

            if item is None:  # Sentinel value to stop
                break

            if isinstance(item, dict):
                if 'scan_info' in item:
                    # Initialize scan info
                    scan_info = item['scan_info']
                elif 'tool_result' in item:
                    # Store tool results
                    tool_name = item['tool_name']
                    tool_data = item['tool_result']
                    tools_info[tool_name] = tool_data
                elif 'findings' in item:
                    # Add findings to buffer
                    findings_buffer.extend(item['findings'])
                elif 'finalize' in item:
                    # Write final results
                    write_final_results(scan_info, findings_buffer, tools_info, item['output_file'])
                    break

        except Empty:
            continue
        except Exception as e:
            logger.error(f"Error in async file writer: {e}")

def write_final_results(scan_info, findings, tools_info, output_file):
    """Write the final JSON results to file."""
    try:
        # Calculate summary
        total_built_in = len(findings)
        total_external = sum(tool_data.get('findings_count', 0) for tool_data in tools_info.values())

        scan_results = {
            "scan_info": scan_info,
            "built_in_findings": findings,
            "external_tools": tools_info,
            "summary": {
                "total_built_in_findings": total_built_in,
                "total_external_findings": total_external,
                "tools_run": len(tools_info),
                "scan_completed": True
            }
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2, ensure_ascii=False)

        logger.info(f"Results written to {output_file}")

    except Exception as e:
        logger.error(f"Error writing final results: {e}")

# Start the async file writer thread
writer_thread = threading.Thread(target=async_file_writer, daemon=True)
writer_thread.start()



# External tools configuration
EXTERNAL_TOOLS = {
    'trufflehog': {
        'command': ['trufflehog', 'filesystem'],
        'args': ['--json', '--no-update'],
        'description': 'TruffleHog - Git history and filesystem scanning'
    },
    'gitleaks': {
        'command': ['gitleaks', 'detect'],
        'args': ['--report-format', 'json', '--report-path', '-'],
        'description': 'Gitleaks - Fast git repository scanning'
    },
    'detect-secrets': {
        'command': ['detect-secrets', 'scan'],
        'args': ['--all-files'],
        'description': 'Detect-Secrets - Code analysis tool'
    },
    'secretlint': {
        'command': ['secretlint'],
        'args': ['--format', 'json'],
        'description': 'Secretlint - Pluggable linting tool'
    }
}

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

def run_external_tool(tool_name, directory):
    """Run an external secret scanning tool"""
    logger.info(f"Attempting to run external tool: {tool_name}")

    if tool_name not in EXTERNAL_TOOLS:
        logger.error(f"Unknown tool: {tool_name}")
        return []

    tool_config = EXTERNAL_TOOLS[tool_name]
    command = tool_config['command'] + tool_config['args']

    # Add directory argument
    if tool_name == 'trufflehog':
        command.append(directory)
    elif tool_name == 'gitleaks':
        command.extend(['--source', directory])
    elif tool_name == 'detect-secrets':
        command.append(directory)
    elif tool_name == 'secretlint':
        command.append(directory)

    logger.info(f"Executing command: {' '.join(command)}")

    try:
        logger.info(f"Running {tool_config['description']}...")
        # Use UTF-8 encoding to handle Unicode characters properly
        # Set environment variables to disable auto-updaters
        env = os.environ.copy()
        env.update({
            'TRUFFLEHOG_NO_UPDATE': '1',
            'NO_UPDATE': '1',
            'DISABLE_AUTO_UPDATE': '1'
        })
        try:
            result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', env=env, timeout=300)  # 5 minute timeout
        except subprocess.TimeoutExpired:
            logger.error(f"{tool_name} timed out after 5 minutes")
            return ""

        # Check if we got any useful output despite errors
        stdout_content = result.stdout.strip() if result.stdout else ""
        stderr_content = result.stderr.strip() if result.stderr else ""

        if result.returncode == 0:
            logger.info(f"{tool_name} completed successfully")
            return stdout_content
        else:
            # Check if there's useful output despite the error (e.g., updater issues)
            if stdout_content and len(stdout_content) > 10:  # Has substantial output
                logger.warning(f"{tool_name} had errors but produced output: {stderr_content[:100]}...")
                return stdout_content
            else:
                logger.error(f"Error running {tool_name}: {stderr_content}")
                return ""
    except FileNotFoundError:
        logger.warning(f"Tool '{tool_name}' not found. Please install it first.")
        return ""
    except Exception as e:
        logger.error(f"Error running {tool_name}: {e}")
        return ""

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
        return []

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

def main():
    logger.info("Secret Scanning Agent started")
    parser = argparse.ArgumentParser(description='Secret Scanning Agent')
    parser.add_argument('directory', help='Directory to scan')
    parser.add_argument('--tools', nargs='+', choices=list(EXTERNAL_TOOLS.keys()),
                       help='Specific external tools to use (default: all available tools)')
    parser.add_argument('--no-external', action='store_true',
                       help='Disable external tools, use only built-in regex scanner')
    parser.add_argument('--output', default='output.json',
                       help='Output file for results (default: output.json)')

    args = parser.parse_args()

    directory = args.directory
    output_file = args.output
    tools = args.tools or []

    # Determine which tools to run
    if args.no_external:
        tools = []
        logger.info("Running with built-in scanner only (external tools disabled)")
    elif args.tools:
        tools = args.tools
        logger.info(f"Using specified external tools: {', '.join(tools)}")
    else:
        tools = list(EXTERNAL_TOOLS.keys())
        logger.info(f"Using all available external tools: {', '.join(tools)}")

    logger.info(f"Scanning directory: {directory}")

    # Initialize scan info and send to async writer
    scan_info = {
        "timestamp": datetime.now().isoformat(),
        "directory": directory,
        "tools_used": ["built-in"] + tools if not args.no_external else ["built-in"],
        "output_file": output_file
    }

    # Send scan info to async writer
    findings_queue.put({'scan_info': scan_info})

    # Run built-in regex scan
    logger.info("Starting built-in regex scan...")
    scan_stats = scan_directory(directory)

    # Run external tools
    external_outputs = []
    external_tool_times = {}
    if tools:
        logger.info(f"Running {len(tools)} external scanning tools...")
        for tool in tools:
            logger.info(f"Running {tool}...")
            tool_start_time = time.time()
            output = run_external_tool(tool, directory)
            tool_time = time.time() - tool_start_time
            external_tool_times[tool] = tool_time

            # Try to parse output for better formatting
            parsed_output = output
            if output:
                if tool == 'trufflehog':
                    # Trufflehog outputs NDJSON (Newline Delimited JSON)
                    try:
                        parsed_output = []
                        for line in output.strip().split('\n'):
                            if line.strip():
                                parsed_output.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass  # Keep as string if parsing fails
                else:
                    # Try to parse as single JSON object
                    try:
                        parsed_output = json.loads(output)
                    except json.JSONDecodeError:
                        pass  # Keep as string if not valid JSON

            # Count findings for summary
            finding_count = 0
            if isinstance(parsed_output, list):
                finding_count = len(parsed_output)
            elif isinstance(parsed_output, dict) and 'results' in parsed_output:
                # For detect-secrets format
                finding_count = sum(len(findings) for findings in parsed_output['results'].values())

            tool_result = {
                "raw_output": parsed_output,
                "status": "completed" if output else "failed/no_output",
                "timestamp": datetime.now().isoformat(),
                "findings_count": finding_count,
                "execution_time": tool_time
            }

            # Send tool result to async writer
            findings_queue.put({'tool_result': tool_result, 'tool_name': tool})
            if output:
                external_outputs.append(f"\n--- {tool.upper()} OUTPUT ---\n{output}")

    # Send finalize signal to async writer
    logger.info("Finalizing results...")
    findings_queue.put({'finalize': True, 'output_file': output_file})

    # Give the writer thread time to finish
    time.sleep(0.1)  # Minimal pause to let async writer complete

    # Display console output
    print(f"\n[*] Results saved to: {output_file}")
    print("=" * 50)

    # Note: We can't display findings here since they're written asynchronously
    # The findings will be shown from the log messages during scanning
    print("\n[SCAN] Findings were displayed in real-time during scanning.")

    # Show external tool status
    if tools:
        print(f"\n[TOOLS] External Tools Status:")
        # Note: We don't have the status info here since it's sent asynchronously
        # This could be improved by keeping a local copy for display
        for tool in tools:
            print(f"  [RUNNING] {tool}")

        # Show external tool outputs
        for output in external_outputs:
            print(output)

    logger.info("Scan completed.")
    print(f"\n[SUMMARY] Scan Results:")
    print(f"   Directory: {directory}")
    print(f"   Files scanned: {scan_stats['scanned_files']}/{scan_stats['total_files']}")
    print(f"   External tools: {len(tools)}")
    print(f"   Results saved to: {output_file}")

    # Display performance statistics
    print(f"\n[PERFORMANCE] Timing Statistics:")
    print(f"   File Discovery: {scan_stats['file_discovery_time']:.2f}s")
    print(f"   Built-in Scan: {scan_stats['scan_time']:.2f}s ({scan_stats['scanned_files']}/{scan_stats['total_files']} files)")
    print(f"   Files per second: {scan_stats['scanned_files']/scan_stats['scan_time']:.1f}" if scan_stats['scan_time'] > 0 else "   Files per second: N/A")

    if tools:
        total_external_time = sum(external_tool_times.values())
        print(f"   External Tools: {total_external_time:.2f}s")
        for tool, tool_time in external_tool_times.items():
            print(f"     - {tool}: {tool_time:.2f}s")

        total_time = scan_stats['file_discovery_time'] + scan_stats['scan_time'] + total_external_time
        print(f"   Total Time: {total_time:.2f}s")
    else:
        total_time = scan_stats['file_discovery_time'] + scan_stats['scan_time']
        print(f"   Total Time: {total_time:.2f}s")

    # Clean up logging listener
    listener.stop()

if __name__ == "__main__":
    main()
