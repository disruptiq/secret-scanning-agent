#!/usr/bin/env python3

import sys
import argparse
import time
import json
import os
from datetime import datetime
from src.secret_scanner.logger import logger, listener
from src.secret_scanner.scanner import scan_directory
from src.tools import EXTERNAL_TOOLS, run_tools
from src.output import findings_queue

def load_config():
    """Load configuration from config.json"""
    config_file = 'config.json'
    if not os.path.exists(config_file):
        logger.warning(f"Configuration file '{config_file}' not found. Using default settings.")
        return {"scannerActive": True, "isActive": {}}

    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        logger.info("Configuration loaded successfully")
        return config
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing config.json: {e}. Using default settings.")
        return {"scannerActive": True, "isActive": {}}
    except Exception as e:
        logger.error(f"Error reading config.json: {e}. Using default settings.")
        return {"scannerActive": True, "isActive": {}}

def main():
    logger.info("Secret Scanning Agent started")

    # Load configuration
    config = load_config()
    is_active = config.get('scannerActive', True)
    builtin_active = config.get('isActive', {}).get('built-in', False)

    if not is_active:
        logger.info("Secret Scanning Agent is disabled via configuration (scannerActive: false)")
        print("WARNING: Secret Scanning Agent is DISABLED via configuration.")
        print("   Set 'scannerActive': true in config.json to enable scanning.")

        # Create disabled output
        disabled_output = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "directory": "(disabled)",
                "tools_used": [],
                "status": "disabled",
                "message": "Scanner is disabled via configuration (scannerActive: false)"
            },
            "built_in_findings": [],
            "external_tools": {},
            "summary": {
                "total_built_in_findings": 0,
                "total_external_findings": 0,
                "tools_run": 0,
                "scan_completed": False,
                "status": "disabled"
            }
        }

        output_file = 'output.json'  # Default output when disabled
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(disabled_output, f, indent=2, ensure_ascii=False)

        print(f"\n[*] Disabled status saved to: {output_file}")
        print("=" * 50)
        print("[SUMMARY] Scanner Status: DISABLED")
        print("   Configuration: scannerActive = false")
        print(f"   Results saved to: {output_file}")

        listener.stop()
        return

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

    # Filter tools based on configuration
    is_active_config = config.get('isActive', {})
    tools = [tool for tool in tools if is_active_config.get(tool, True)]
    if tools:
        logger.info(f"Active external tools after config filter: {', '.join(tools)}")
    else:
        logger.info("No external tools active per configuration")

    logger.info(f"Scanning directory: {directory}")

    # Initialize scan info and send to async writer
    builtin_in_tools = ["built-in"] if builtin_active else []
    scan_info = {
    "timestamp": datetime.now().isoformat(),
    "directory": directory,
    "tools_used": builtin_in_tools + tools if not args.no_external else builtin_in_tools,
        "output_file": output_file
    }

    # Send scan info to async writer
    findings_queue.put({'scan_info': scan_info})

    # Run built-in regex scan
    if builtin_active:
        logger.info("Starting built-in regex scan...")
        scan_stats = scan_directory(directory)
    else:
        logger.info("Built-in scanner disabled per configuration")
        scan_stats = {'file_discovery_time': 0.0, 'scan_time': 0.0, 'total_files': 0, 'scanned_files': 0, 'findings_count': 0}

    # Run external tools using the new run_tools function
    external_outputs, external_tool_times = run_tools(directory, tools)

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
