import json
import threading
from datetime import datetime
from queue import Queue, Empty
from src.secret_scanner.logger import logger

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
