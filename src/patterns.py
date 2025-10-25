import re
import math
from typing import List, Dict, Any, Optional, Tuple

# Compiled regex patterns for better performance
SECRET_PATTERNS = [
    # AWS Credentials
    {
        'name': 'AWS Access Key ID',
        'pattern': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
        'confidence': 'high',
        'description': 'AWS Access Key ID'
    },
    {
        'name': 'AWS Secret Access Key',
        'pattern': re.compile(r'\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'),
        'confidence': 'high',
        'description': 'AWS Secret Access Key'
    },
    {
        'name': 'AWS Session Token',
        'pattern': re.compile(r'\b(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{300,500})["\']?'),
        'confidence': 'high',
        'description': 'AWS Session Token'
    },

    # GitHub Tokens
    {
        'name': 'GitHub Personal Access Token',
        'pattern': re.compile(r'\bghp_[A-Za-z0-9]{36}\b'),
        'confidence': 'high',
        'description': 'GitHub Personal Access Token'
    },
    {
        'name': 'GitHub OAuth Access Token',
        'pattern': re.compile(r'\bgho_[A-Za-z0-9]{36}\b'),
        'confidence': 'high',
        'description': 'GitHub OAuth Access Token'
    },
    {
        'name': 'GitHub App Token',
        'pattern': re.compile(r'\b(?:ghu_|github_pat_)[A-Za-z0-9]{36,255}\b'),
        'confidence': 'high',
        'description': 'GitHub App or PAT Token'
    },

    # Google Cloud
    {
        'name': 'Google API Key',
        'pattern': re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
        'confidence': 'high',
        'description': 'Google API Key'
    },
    {
        'name': 'Google Cloud Service Account Key',
        'pattern': re.compile(r'\bAIza[0-9A-Za-z-_]{35}\b'),
        'confidence': 'high',
        'description': 'Google Cloud Service Account'
    },

    # Stripe
    {
        'name': 'Stripe Secret Key',
        'pattern': re.compile(r'\bsk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
        'confidence': 'high',
        'description': 'Stripe Secret Key'
    },
    {
        'name': 'Stripe Restricted Key',
        'pattern': re.compile(r'\brk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
        'confidence': 'high',
        'description': 'Stripe Restricted Key'
    },
    {
        'name': 'Stripe Publishable Key',
        'pattern': re.compile(r'\bpk_(?:live|test)_[0-9a-zA-Z]{24}\b'),
        'confidence': 'medium',
        'description': 'Stripe Publishable Key'
    },

    # Slack
    {
        'name': 'Slack OAuth Token',
        'pattern': re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b'),
        'confidence': 'high',
        'description': 'Slack OAuth Token'
    },
    {
        'name': 'Slack Webhook URL',
        'pattern': re.compile(r'\bhttps://hooks\.slack\.com/services/T[0-9A-Z]{10}/B[0-9A-Z]{10}/[0-9A-Za-z]{24}\b'),
        'confidence': 'high',
        'description': 'Slack Webhook URL'
    },

    # Database and Generic Passwords
    {
        'name': 'Database Password',
        'pattern': re.compile(r'\b(?:password|passwd|pwd|db_pass|database_password)\s*[:=]\s*["\']?([^"\']{8,})["\']?', re.IGNORECASE),
        'confidence': 'medium',
        'description': 'Database Password'
    },
    {
        'name': 'Generic Password',
        'pattern': re.compile(r'\b(?:password|passwd|pwd)\s*[:=]\s*["\']?([^"\']{8,})["\']?', re.IGNORECASE),
        'confidence': 'medium',
        'description': 'Generic Password'
    },

    # JWT Tokens
    {
        'name': 'JWT Token',
        'pattern': re.compile(r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b'),
        'confidence': 'medium',
        'description': 'JSON Web Token'
    },

    # OAuth Tokens
    {
        'name': 'OAuth Access Token',
        'pattern': re.compile(r'\b(?:access_token|oauth_token)\s*[:=]\s*["\']?([A-Za-z0-9]{32,})["\']?', re.IGNORECASE),
        'confidence': 'medium',
        'description': 'OAuth Access Token'
    },
    {
        'name': 'Bearer Token',
        'pattern': re.compile(r'\b(?:bearer|authorization)\s+["\']?([A-Za-z0-9]{32,})["\']?', re.IGNORECASE),
        'confidence': 'medium',
        'description': 'Bearer Token'
    },

    # API Keys (Generic)
    {
        'name': 'Generic API Key',
        'pattern': re.compile(r'\b(?:api[_-]?key|apikey|api_key)\s*[:=]\s*["\']?([A-Za-z0-9]{20,})["\']?', re.IGNORECASE),
        'confidence': 'low',
        'description': 'Generic API Key'
    },

    # Private Keys
    {
        'name': 'RSA Private Key',
        'pattern': re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        'confidence': 'high',
        'description': 'RSA Private Key'
    },
    {
        'name': 'EC Private Key',
        'pattern': re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        'confidence': 'high',
        'description': 'EC Private Key'
    },
    {
        'name': 'DSA Private Key',
        'pattern': re.compile(r'-----BEGIN DSA PRIVATE KEY-----'),
        'confidence': 'high',
        'description': 'DSA Private Key'
    },
    {
        'name': 'SSH Private Key',
        'pattern': re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        'confidence': 'high',
        'description': 'SSH Private Key'
    },

    # Other Cloud Providers
    {
        'name': 'Azure Storage Key',
        'pattern': re.compile(r'\b[A-Za-z0-9+/]{88}==\b'),
        'confidence': 'medium',
        'description': 'Azure Storage Account Key'
    },
    {
        'name': 'Azure Client Secret',
        'pattern': re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'),
        'confidence': 'low',
        'description': 'Azure Client Secret (GUID format)'
    },

    # Docker and Container Registry
    {
        'name': 'Docker Hub Token',
        'pattern': re.compile(r'\bdckr_pat_[A-Za-z0-9]{27}_[A-Za-z0-9]{52}\b'),
        'confidence': 'high',
        'description': 'Docker Hub Personal Access Token'
    },

    # DigitalOcean
    {
        'name': 'DigitalOcean Token',
        'pattern': re.compile(r'\bdoo_v1_[a-f0-9]{64}\b'),
        'confidence': 'high',
        'description': 'DigitalOcean API Token'
    },

    # Mail Services
    {
        'name': 'SendGrid API Key',
        'pattern': re.compile(r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b'),
        'confidence': 'high',
        'description': 'SendGrid API Key'
    },
    {
        'name': 'Mailgun API Key',
        'pattern': re.compile(r'\bkey-[a-f0-9]{32}\b'),
        'confidence': 'medium',
        'description': 'Mailgun API Key'
    },

    # Payment Processors
    {
        'name': 'PayPal Client Secret',
        'pattern': re.compile(r'\b[A-Za-z0-9]{80,}\b'),
        'confidence': 'medium',
        'description': 'PayPal Client Secret'
    },

    # Twilio
    {
        'name': 'Twilio Auth Token',
        'pattern': re.compile(r'\bSK[0-9a-f]{32}\b'),
        'confidence': 'high',
        'description': 'Twilio Auth Token'
    },

    # NPM
    {
        'name': 'NPM Token',
        'pattern': re.compile(r'\bnpm_[A-Za-z0-9]{36}\b'),
        'confidence': 'high',
        'description': 'NPM Access Token'
    },

    # PyPI
    {
        'name': 'PyPI API Token',
        'pattern': re.compile(r'\bpypi-[A-Za-z0-9]{50,}\b'),
        'confidence': 'high',
        'description': 'PyPI API Token'
    },
]

# High-entropy string patterns (fallback for unknown secrets)
HIGH_ENTROPY_PATTERNS = [
    {
        'name': 'High Entropy String (32+ chars)',
        'min_length': 32,
        'pattern': re.compile(r'\b[A-Za-z0-9+/=]{32,}\b'),
        'confidence': 'low'
    },
    {
        'name': 'High Entropy String (20+ chars)',
        'min_length': 20,
        'pattern': re.compile(r'\b[A-Fa-f0-9]{20,}\b'),
        'confidence': 'low'
    },
]

# Context keywords that suggest a line contains a secret
SECRET_CONTEXT_KEYWORDS = {
    'high': [
        'secret', 'token', 'key', 'password', 'credential', 'auth',
        'private', 'access', 'session', 'bearer', 'authorization',
        'api_key', 'apikey', 'access_token', 'refresh_token'
    ],
    'medium': [
        'config', 'env', 'environment', 'setting', 'variable',
        'credential', 'auth', 'login'
    ]
}

# Patterns to exclude (common false positives)
EXCLUDE_PATTERNS = [
    re.compile(r'\b(?:test|example|sample|demo|fake|placeholder)\b', re.IGNORECASE),
    re.compile(r'\b(?:version|commit|hash|id)\b.*[:=].*[a-f0-9]{8,}', re.IGNORECASE),
    re.compile(r'\b(?:md5|sha1|sha256|sha512)\b.*[:=].*[a-f0-9]{8,}', re.IGNORECASE),
    re.compile(r'\b(?:uuid|guid)\b.*[:=].*[a-f0-9-]{8,}', re.IGNORECASE),
    re.compile(r'\b(?:comment|todo|fixme|hack)\b', re.IGNORECASE),
    re.compile(r'\b(?:http|https|ftp)://[^\s]*', re.IGNORECASE),  # URLs
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Emails
]

def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    length = len(text)
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def has_secret_context(line: str, keywords: List[str]) -> bool:
    """Check if line contains secret-related context keywords."""
    line_lower = line.lower()
    return any(keyword in line_lower for keyword in keywords)

def is_likely_false_positive(line: str, match: str) -> bool:
    """Check if a match is likely a false positive."""
    for pattern in EXCLUDE_PATTERNS:
        if pattern.search(line):
            return True

    # Check if match appears to be a common non-secret pattern
    if re.match(r'^[a-f0-9]{8,}$', match) and len(match) < 32:
        # Short hex strings are often hashes/IDs, not secrets
        return True

    if re.match(r'^\d+$', match):
        # Pure numeric strings are rarely secrets
        return True

    return False

def find_high_entropy_strings(line: str, min_length: int = 20, min_entropy: float = 4.0) -> List[str]:
    """Find high-entropy strings in a line."""
    matches = []
    words = re.findall(r'\b[A-Za-z0-9+/=]{' + str(min_length) + r',}\b', line)

    for word in words:
        if calculate_entropy(word) >= min_entropy and not is_likely_false_positive(line, word):
            matches.append(word)

    return matches

def find_secrets_in_file(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    Find secrets in file content using pattern matching and entropy analysis.
    """
    findings = []
    lines = content.split('\n')

    for line_num, line in enumerate(lines, 1):
        # Skip empty lines
        if not line.strip():
            continue

        # Check predefined patterns
        for pattern_info in SECRET_PATTERNS:
            pattern = pattern_info['pattern']
            matches = pattern.findall(line)

            for match in matches:
                # Handle patterns that capture groups
                if isinstance(match, tuple):
                    match = match[0] if match[0] else ''.join(match)

                if not match:
                    continue

                # Skip likely false positives
                if is_likely_false_positive(line, match):
                    continue

                # Check context for medium/low confidence patterns
                has_context = has_secret_context(line, SECRET_CONTEXT_KEYWORDS['high'])
                if pattern_info['confidence'] in ['low', 'medium'] and not has_context:
                    has_context = has_secret_context(line, SECRET_CONTEXT_KEYWORDS['medium'])
                    if not has_context:
                        continue

                findings.append({
                    'file': file_path,
                    'line': line_num,
                    'type': pattern_info['name'],
                    'match': match,
                    'confidence': pattern_info['confidence'],
                    'context': line.strip(),
                    'description': pattern_info['description']
                })

        # Check for high-entropy strings not caught by patterns
        if not any(f['line'] == line_num for f in findings):  # Avoid duplicate detection
            high_entropy_matches = find_high_entropy_strings(line)
            for match in high_entropy_matches:
                # Check if this match was already found by a pattern
                if not any(f['match'] == match for f in findings if f['line'] == line_num):
                    findings.append({
                        'file': file_path,
                        'line': line_num,
                        'type': 'High Entropy String',
                        'match': match,
                        'confidence': 'low',
                        'context': line.strip(),
                        'description': f'High-entropy string ({len(match)} chars)'
                    })

    return findings
