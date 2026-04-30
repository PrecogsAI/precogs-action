/**
 * Secret + PII Scanner — FREE tier (runs locally, no API call)
 *
 * Uses regex patterns + Shannon entropy to detect:
 * - API keys (AWS, GCP, Stripe, GitHub, etc.)
 * - Passwords / tokens in code
 * - PII patterns (emails, SSNs, credit cards, phone numbers)
 * - Private keys / certificates
 * - Connection strings / database URLs
 */

const fs = require('fs');
const path = require('path');

// ─── Secret patterns ────────────────────────────────────────────────────────

const SECRET_PATTERNS = [
  // AWS
  { id: 'aws-access-key', regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g, title: 'AWS Access Key ID', severity: 'critical', cwe: 'CWE-798' },
  { id: 'aws-secret-key', regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/g, title: 'AWS Secret Access Key', severity: 'critical', cwe: 'CWE-798' },

  // GitHub
  { id: 'github-pat', regex: /ghp_[A-Za-z0-9_]{36,}/g, title: 'GitHub Personal Access Token', severity: 'critical', cwe: 'CWE-798' },
  { id: 'github-oauth', regex: /gho_[A-Za-z0-9_]{36,}/g, title: 'GitHub OAuth Token', severity: 'critical', cwe: 'CWE-798' },
  { id: 'github-app', regex: /(?:ghu|ghs)_[A-Za-z0-9_]{36,}/g, title: 'GitHub App Token', severity: 'critical', cwe: 'CWE-798' },

  // Google / GCP
  { id: 'gcp-api-key', regex: /AIza[0-9A-Za-z_-]{35}/g, title: 'Google API Key', severity: 'high', cwe: 'CWE-798' },
  { id: 'gcp-service-account', regex: /"type"\s*:\s*"service_account"/g, title: 'GCP Service Account Key File', severity: 'critical', cwe: 'CWE-798' },

  // Stripe
  { id: 'stripe-secret', regex: /sk_live_[0-9a-zA-Z]{24,}/g, title: 'Stripe Secret Key', severity: 'critical', cwe: 'CWE-798' },
  { id: 'stripe-publishable', regex: /pk_live_[0-9a-zA-Z]{24,}/g, title: 'Stripe Publishable Key (live)', severity: 'medium', cwe: 'CWE-798' },

  // Slack
  { id: 'slack-token', regex: /xox[bpors]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}/g, title: 'Slack Token', severity: 'high', cwe: 'CWE-798' },
  { id: 'slack-webhook', regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g, title: 'Slack Webhook URL', severity: 'high', cwe: 'CWE-798' },

  // Twilio
  { id: 'twilio-api-key', regex: /SK[0-9a-fA-F]{32}/g, title: 'Twilio API Key', severity: 'high', cwe: 'CWE-798' },

  // SendGrid
  { id: 'sendgrid-api', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, title: 'SendGrid API Key', severity: 'high', cwe: 'CWE-798' },

  // Database URLs
  { id: 'db-connection-string', regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s'"]+/g, title: 'Database Connection String', severity: 'high', cwe: 'CWE-798' },

  // Private keys
  { id: 'private-key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, title: 'Private Key', severity: 'critical', cwe: 'CWE-321' },

  // JWT tokens
  { id: 'jwt-token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, title: 'JWT Token', severity: 'high', cwe: 'CWE-798' },

  // Generic secrets (assignment patterns)
  { id: 'generic-secret', regex: /(?:password|passwd|secret|api_key|apikey|api_secret|access_token|auth_token|private_key)\s*[=:]\s*['"][^'"]{8,}['"]/gi, title: 'Hardcoded Secret', severity: 'high', cwe: 'CWE-798' },

  // OpenAI
  { id: 'openai-key', regex: /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/g, title: 'OpenAI API Key', severity: 'critical', cwe: 'CWE-798' },
];

// ─── PII patterns ───────────────────────────────────────────────────────────

const PII_PATTERNS = [
  { id: 'email-address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, title: 'Email Address (potential PII)', severity: 'low', cwe: 'CWE-359', minContext: true },
  { id: 'ssn', regex: /\b\d{3}-\d{2}-\d{4}\b/g, title: 'Social Security Number', severity: 'critical', cwe: 'CWE-359' },
  { id: 'credit-card', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, title: 'Credit Card Number', severity: 'critical', cwe: 'CWE-359' },
  { id: 'phone-number', regex: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, title: 'Phone Number (potential PII)', severity: 'low', cwe: 'CWE-359', minContext: true },
  { id: 'ip-address', regex: /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g, title: 'Hardcoded IP Address', severity: 'low', cwe: 'CWE-798' },
];

// ─── File walking ───────────────────────────────────────────────────────────

const IGNORE_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'vendor', '.next', '__pycache__',
  '.venv', 'venv', 'coverage', '.nyc_output', '.terraform', '.cache',
]);

const SCAN_EXTENSIONS = new Set([
  '.js', '.ts', '.jsx', '.tsx', '.py', '.rb', '.php', '.java', '.go',
  '.cs', '.c', '.cpp', '.rs', '.swift', '.kt', '.scala', '.sh', '.bash',
  '.yml', '.yaml', '.json', '.xml', '.toml', '.ini', '.cfg', '.conf',
  '.env', '.properties', '.tf', '.hcl', '.sol', '.vue', '.dart',
]);

function walkFiles(dir, files = []) {
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      if (entry.name.startsWith('.') && entry.name !== '.env') continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        walkFiles(fullPath, files);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        // Always scan .env files
        if (entry.name === '.env' || entry.name.startsWith('.env.') || SCAN_EXTENSIONS.has(ext)) {
          // Skip large files (>500KB)
          try {
            const stat = fs.statSync(fullPath);
            if (stat.size < 500 * 1024) {
              files.push(fullPath);
            }
          } catch {}
        }
      }
    }
  } catch {}
  return files;
}

// ─── Shannon entropy (detect high-entropy strings = likely secrets) ─────────

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ─── Main scanner ───────────────────────────────────────────────────────────

async function scanSecrets(workspace) {
  const findings = [];
  const files = walkFiles(workspace);
  const seenKeys = new Set(); // dedup

  for (const filePath of files) {
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch { continue; }

    const relativePath = path.relative(workspace, filePath);
    const lines = content.split('\n');

    // Check each pattern
    for (const pattern of [...SECRET_PATTERNS, ...PII_PATTERNS]) {
      // Reset regex lastIndex
      pattern.regex.lastIndex = 0;

      let match;
      while ((match = pattern.regex.exec(content)) !== null) {
        const matchStr = match[0];

        // Dedup
        const key = `${pattern.id}:${relativePath}:${matchStr.slice(0, 20)}`;
        if (seenKeys.has(key)) continue;
        seenKeys.add(key);

        // For PII patterns with minContext, check if it looks like test data
        if (pattern.minContext) {
          // Skip test/example files
          if (relativePath.includes('test') || relativePath.includes('example') ||
              relativePath.includes('fixture') || relativePath.includes('mock')) {
            continue;
          }
        }

        // For generic secrets, verify high entropy
        if (pattern.id === 'generic-secret') {
          const value = match[0].split(/[=:]\s*['"]?/)[1]?.replace(/['"]$/, '') || '';
          if (shannonEntropy(value) < 3.5) continue; // low entropy = likely not a real secret
        }

        // Find line number
        const beforeMatch = content.slice(0, match.index);
        const lineNumber = (beforeMatch.match(/\n/g) || []).length + 1;

        findings.push({
          type: pattern.id.startsWith('email') || pattern.id.startsWith('ssn') ||
                pattern.id.startsWith('credit') || pattern.id.startsWith('phone')
                ? 'pii' : 'secret',
          title: pattern.title,
          severity: pattern.severity,
          file: relativePath,
          line: lineNumber,
          cwe: pattern.cwe,
          description: `Found ${pattern.title} in \`${relativePath}\` at line ${lineNumber}`,
          match: matchStr.slice(0, 8) + '***' + matchStr.slice(-4), // redact middle
        });
      }
    }
  }

  return findings;
}

module.exports = { scanSecrets };
