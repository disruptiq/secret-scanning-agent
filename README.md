# Secret Scanning Agent

## Overview

A comprehensive secret scanning tool that scans directories for potential secrets like API keys, passwords, tokens, and credentials. It combines built-in regex patterns with industry-standard secret scanning tools for maximum detection coverage.

## Features

- **Built-in Regex Engine**: Fast scanning with 9+ secret patterns (AWS keys, GitHub tokens, API keys, etc.)
- **Multi-Tool Integration**: Supports TruffleHog, Gitleaks, Detect-Secrets, and Secretlint
- **Default All-Tools Mode**: Automatically runs all available tools by default
- **Flexible Configuration**: Choose all tools, specific tools, or built-in only
- **Detailed Logging**: Real-time progress tracking and error handling
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Comprehensive Output**: Console results + JSON output from external tools

## Installation

### Prerequisites

- Python 3.6+
- Git (for some external tools)

### Installing the Agent

```bash
git clone https://github.com/your-org/secret-scanning-agent.git
cd secret-scanning-agent
pip install -r requirements.txt
```

### Installing External Tools (Optional but Recommended)

The agent can use popular secret scanning tools for enhanced detection. Currently working tools:

- ✅ **TruffleHog**: Download from https://github.com/trufflesecurity/trufflehog/releases (working)
- ❌ **Gitleaks**: Download from https://github.com/gitleaks/gitleaks/releases (installation issues)
- ✅ **Detect-Secrets**: `pip install detect-secrets` (working)
- ❌ **Secretlint**: `npm install -g secretlint @secretlint/secretlint-rule-preset-recommend` (path issues)

## Configuration

The agent can be configured via `config.json` file. Create this file in the same directory as the agent.

### Configuration Parameters

- **`isActive`** (boolean): Enable/disable the entire secret scanning functionality
  - `true`: Enable scanning (default)
  - `false`: Disable all scanners and return disabled status

### Example config.json

```json
{
  "isActive": true,
  "description": "Set to true to enable secret scanning functionality, false to disable all scanners",
  "scanner": {
    "max_file_size_mb": 100,
    "use_multiprocessing": true,
    "log_level": "INFO"
  },
  "output": {
    "format": "json",
    "include_timestamps": true
  }
}
```

### Disabled Mode

When `isActive` is set to `false`, the agent will:
- Skip all scanning operations
- Return a disabled status in the output file
- Display a warning message to the user

```bash
python main.py /path/to/project
# ⚠️  Secret Scanning Agent is DISABLED via configuration.
#    Set 'isActive': true in config.json to enable scanning.
```

## Usage

### Default Mode (All Tools)

By default, the agent runs all available tools:

```bash
python main.py /path/to/project
```

This will run:
- Built-in regex scanner
- All installed external tools (TruffleHog, Gitleaks, Detect-Secrets, Secretlint)

### Specific Tools Only

You can specify which external tools to use:

```bash
python main.py /path/to/project --tools trufflehog gitleaks
```

### Built-in Scanner Only

To use only the built-in regex scanner:

```bash
python main.py /path/to/project --no-external
```

### Custom Output File

Save results to a custom JSON file:

```bash
python main.py /path/to/project --output scan-results.json
```

### Help

```bash
python main.py --help
```

## Supported Tools

### Built-in Regex Patterns
- AWS Access Key IDs and Secret Keys
- GitHub Personal Access Tokens
- Generic API Keys
- Stripe Secret Keys
- Google API Keys
- Slack Bot Tokens
- Database Passwords
- Private Keys (SSH/RSA/EC/DSA)
- Basic Auth Credentials

### External Tools Integration
- ✅ **TruffleHog**: Advanced git history and filesystem scanning (working)
- ❌ **Gitleaks**: Fast git repository scanning with extensive rule sets (installation issues)
- ✅ **Detect-Secrets**: Yelp's code analysis tool with 29+ detection plugins (working)
- ❌ **Secretlint**: Pluggable linting tool for various secret types (path issues)

## Output

### JSON Output File (output.json) - Saved by Default

All results are automatically saved to `output.json` with comprehensive structured data:

```json
{
  "scan_info": {
    "timestamp": "2025-10-22T17:50:28.000000",
    "directory": "/path/to/project",
    "tools_used": ["built-in", "trufflehog", "gitleaks", "detect-secrets", "secretlint"],
    "output_file": "output.json"
  },
  "built_in_findings": [
    {
      "file": "config/.env",
      "line": 5,
      "type": "AWS Access Key",
      "match": "AKIAIOSFODNN7EXAMPLE"
    }
  ],
  "external_tools": {
    "detect-secrets": {
      "raw_output": "{...}",
      "status": "completed",
      "timestamp": "2025-10-22T17:50:35.000000"
    }
  },
  "summary": {
    "total_built_in_findings": 7,
    "tools_run": 4,
    "scan_completed": true
  }
}
```

### Console Output Examples

#### Built-in Scanner Results
```
📄 Results saved to: output.json
==================================================

🔍 BUILT-IN REGEX FINDINGS:
  • test-secrets\.env:1 - AWS Access Key
  • test-secrets\.env:2 - AWS Secret Key
  • test-secrets\.env:4 - GitHub Token

✅ Built-in scan found 7 potential secrets.

🔧 External Tools Status:
  ✅ trufflehog: completed
  ❌ gitleaks: failed/no_output
  ✅ detect-secrets: completed
  ❌ secretlint: failed/no_output

🎯 Scan Summary:
   Directory: test-secrets
   Built-in findings: 7
   External tools: 4
   Results saved to: output.json
```

### Detect-Secrets JSON Output
```json
{
  "results": {
    "test-secrets\\.env": [
      {
        "type": "GitHub Token",
        "filename": "test-secrets\\.env",
        "line_number": 4,
        "is_verified": false
      }
    ]
  }
}
```

## Configuration

### Adding Custom Patterns

Edit `patterns.py` to add new secret patterns:

```python
{
    'name': 'Custom API Key',
    'pattern': r'custom[_-]?key[_-]?[a-zA-Z0-9]{32}',
}
```

### Tool-Specific Configuration

Each external tool can be configured via its own config files:
- TruffleHog: Command-line flags
- Gitleaks: `gitleaks.toml` config file
- Detect-Secrets: Baseline files and plugins
- Secretlint: `.secretlintrc.json` config

## Testing

The agent includes test data in the `test-secrets/` directory with various secret types for verification:

```bash
python main.py test-secrets
```

## Security Considerations

- **Review Results**: Always manually review findings before taking action
- **False Positives**: Some detections may be false positives (test data, examples, etc.)
- **Permissions**: Ensure appropriate access permissions for scanned directories
- **Data Handling**: Secrets are displayed but not stored persistently

## Development

### Adding New Tools

1. Add tool configuration to `EXTERNAL_TOOLS` dict in `main.py`
2. Implement command-line arguments handling
3. Test with sample data

### Extending Built-in Patterns

1. Add new patterns to `SECRET_PATTERNS` in `patterns.py`
2. Test with sample data containing the new pattern
3. Update documentation

## Architecture

```
Secret Scanning Agent
├── main.py (CLI interface and orchestration)
├── logger.py (Asynchronous logging setup)
├── scanner.py (Core scanning logic and multiprocessing)
├── tools.py (External tools configuration and execution)
├── output.py (Asynchronous file writing and results)
├── patterns.py (Built-in regex patterns)
├── config.json (Configuration file)
├── test-secrets/ (Test data with dummy secrets)
└── External Tools (optional)
    ├── TruffleHog
    ├── Gitleaks
    ├── Detect-Secrets
    └── Secretlint
```

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Disclaimer

This tool helps identify potential secrets but should not be relied upon as the sole method of secret detection. Always combine automated scanning with manual code reviews and security best practices.
