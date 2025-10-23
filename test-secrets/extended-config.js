// Test file for various secret types
const config = {
  // AWS
  awsAccessKey: 'AKIAIOSFODNN7EXAMPLE',
  awsSecretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',

  // GitHub
  githubToken: 'ghp_1234567890abcdef1234567890abcdef12345678',
  githubPAT: 'github_pat_11A2B3C4D_abcdef1234567890abcdef1234567890abcdef',

  // Slack
  slackToken: 'xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx',

  // JWT
  jwtToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',

  // OAuth
  accessToken: 'ya29.a0AfH6SMAW1XvJ9Q1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z',

  // Generic API Key
  apiKey: 'sk-1234567890abcdef1234567890abcdef1234567890',

  // False positives (should be filtered out)
  version: '1.2.3',
  commit: 'abc123def456',
  uuid: '550e8400-e29b-41d4-a716-446655440000',
  url: 'https://example.com/api/v1/users',

  // Real password (should be detected)
  dbPassword: 'MySecurePassword123!@#',
  adminPassword: 'AdminPass2023$%^'
};
