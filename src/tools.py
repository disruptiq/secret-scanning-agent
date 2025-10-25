import os
import subprocess
import json
import time
from datetime import datetime
from src.secret_scanner.logger import logger

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

def run_external_tool(tool_name, directory):
    """Run an external secret scanning tool"""
    logger.info(f"Attempting to run external tool: {tool_name}")

    if tool_name not in EXTERNAL_TOOLS:
        logger.error(f"Unknown tool: {tool_name}")
        return ""

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

def run_tools(directory, tools):
    """Run external tools and return their results"""
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
            from src.output import findings_queue
            findings_queue.put({'tool_result': tool_result, 'tool_name': tool})
            if output:
                external_outputs.append(f"\n--- {tool.upper()} OUTPUT ---\n{output}")

    return external_outputs, external_tool_times
