#!/usr/bin/env python3

import sys
import os
import subprocess
import argparse
import logging
import json
from datetime import datetime
from pathlib import Path
from patterns import find_secrets_in_file

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
    except:
        return False

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
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', env=env)

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
    """Scan a directory for potential secrets"""
    logger.info(f"Starting directory scan: {directory}")
    findings = []
    dir_path = Path(directory)

    if not dir_path.exists():
        logger.error(f"Directory '{directory}' does not exist.")
        return findings

    logger.info(f"Scanning directory: {directory}")

    # Find all files, excluding common binary extensions
    exclude_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
                         '.mp3', '.mp4', '.avi', '.mov', '.zip', '.tar', '.gz',
                         '.exe', '.dll', '.so', '.dylib', '.pyc', '.class'}

    total_files = 0
    scanned_files = 0

    for file_path in dir_path.rglob('*'):
        if file_path.is_file():
            total_files += 1
            if file_path.suffix.lower() in exclude_extensions:
                logger.debug(f"Skipping binary file: {file_path}")
                continue
            if not is_text_file(file_path):
                logger.debug(f"Skipping non-text file: {file_path}")
                continue

            try:
                logger.debug(f"Scanning file: {file_path}")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_findings = find_secrets_in_file(str(file_path), content)
                    findings.extend(file_findings)
                    if file_findings:
                        # Group findings by confidence for better logging
                        high_conf = sum(1 for f in file_findings if f.get('confidence') == 'high')
                        medium_conf = sum(1 for f in file_findings if f.get('confidence') == 'medium')
                        low_conf = sum(1 for f in file_findings if f.get('confidence') == 'low')
                        logger.info(f"Found {len(file_findings)} secrets in {file_path} (high:{high_conf}, medium:{medium_conf}, low:{low_conf})")
                scanned_files += 1
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")
                continue

    logger.info(f"Scan complete: {scanned_files}/{total_files} files scanned, {len(findings)} findings")
    return findings

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

    # Initialize results structure
    scan_results = {
        "scan_info": {
            "timestamp": datetime.now().isoformat(),
            "directory": directory,
            "tools_used": ["built-in"] + tools if not args.no_external else ["built-in"],
            "output_file": output_file
        },
        "built_in_findings": [],
        "external_tools": {},
        "summary": {
            "total_built_in_findings": 0,
            "total_external_findings": 0,
            "tools_run": len(tools),
        "scan_completed": False
        }
    }

    # Run built-in regex scan
    logger.info("Starting built-in regex scan...")
    findings = scan_directory(directory)
    scan_results["built_in_findings"] = findings
    scan_results["summary"]["total_built_in_findings"] = len(findings)

    # Run external tools
    external_outputs = []
    if tools:
        logger.info(f"Running {len(tools)} external scanning tools...")
        for tool in tools:
            logger.info(f"Running {tool}...")
            output = run_external_tool(tool, directory)
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

            scan_results["external_tools"][tool] = {
                "raw_output": parsed_output,
                "status": "completed" if output else "failed/no_output",
                "timestamp": datetime.now().isoformat(),
                "findings_count": finding_count
            }
            if output:
                external_outputs.append(f"\n--- {tool.upper()} OUTPUT ---\n{output}")

    # Calculate total external findings
    total_external = sum(tool_data.get('findings_count', 0) for tool_data in scan_results['external_tools'].values())
    scan_results["summary"]["total_external_findings"] = total_external

    # Mark scan as completed
    scan_results["summary"]["scan_completed"] = True

    # Write results to JSON file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2, ensure_ascii=False)
        logger.info(f"Results written to {output_file}")
    except Exception as e:
        logger.error(f"Failed to write results to {output_file}: {e}")

    # Display console output
    print(f"\n[*] Results saved to: {output_file}")
    print("=" * 50)

    if findings:
        logger.info("Displaying built-in regex findings")
        print("\n[SCAN] BUILT-IN REGEX FINDINGS:")
        for finding in findings:
            print(f"  - {finding['file']}:{finding['line']} - {finding['type']}")
        total_findings = len(findings)
        print(f"\n[SUCCESS] Built-in scan found {total_findings} potential secrets.")
    else:
        total_findings = 0
        print("\n[SUCCESS] Built-in scan found no potential secrets.")

    # Show external tool status
    if tools:
        print(f"\n[TOOLS] External Tools Status:")
        for tool in tools:
            status = scan_results["external_tools"][tool]["status"]
            status_icon = "[OK]" if status == "completed" else "[FAIL]"
            print(f"  {status_icon} {tool}: {status}")

        # Show external tool outputs
        for output in external_outputs:
            print(output)

    logger.info(f"Scan completed. Total built-in findings: {total_findings}")
    print(f"\n[SUMMARY] Scan Results:")
    print(f"   Directory: {directory}")
    print(f"   Built-in findings: {total_findings}")
    if tools:
        total_external = scan_results["summary"].get("total_external_findings", 0)
        print(f"   External findings: {total_external}")
    print(f"   External tools: {len(tools)}")
    print(f"   Results saved to: {output_file}")

if __name__ == "__main__":
    main()
