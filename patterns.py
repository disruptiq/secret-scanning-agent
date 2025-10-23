import re

# Common secret patterns
SECRET_PATTERNS = [
    {
        'name': 'AWS Access Key',
        'pattern': r'AKIA[0-9A-Z]{16}',
    },
    {
        'name': 'AWS Secret Key',
        'pattern': r'(?i)aws_secret_access_key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
    },
    {
        'name': 'Generic API Key',
        'pattern': r'(?i)api[_-]?key[_-]?[a-zA-Z0-9]{20,}',
    },
    {
        'name': 'GitHub Token',
        'pattern': r'ghp_[A-Za-z0-9]{36}',
    },
    {
        'name': 'Slack Token',
        'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
    },
    {
        'name': 'Google API Key',
        'pattern': r'AIza[0-9A-Za-z-_]{35}',
    },
    {
        'name': 'Stripe Secret Key',
        'pattern': r'sk_live_[0-9a-zA-Z]{24}',
    },
    {
        'name': 'Database Password',
        'pattern': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^"\']{8,}["\']?',
    },
    {
        'name': 'Private Key',
        'pattern': r'-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----',
    },
]

def find_secrets_in_file(file_path, content):
    findings = []
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        for pattern_info in SECRET_PATTERNS:
            matches = re.findall(pattern_info['pattern'], line)
            if matches:
                findings.append({
                    'file': file_path,
                    'line': line_num,
                    'type': pattern_info['name'],
                    'match': matches[0] if matches else 'pattern matched'
                })
    return findings
