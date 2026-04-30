# ⚡ Precogs Security Scan

AI-powered security scanner that finds vulnerabilities, secrets, PII, and insecure dependencies in your code.

**Free secret + dependency scanning included** — no API key required.

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Precogs%20Security%20Scan-purple?style=for-the-badge&logo=github)](https://github.com/marketplace/actions/precogs-security-scan)

---

## 🚀 Quick Start

### Free — Secrets, PII & Dependency Scanning (no API key)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  precogs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: PrecogsAI/precogs-action@v1
```

That's it. Finds hardcoded secrets, API keys, PII, vulnerable dependencies (via OSV.dev), and private keys.

### Pro — Full Security Suite (with API key)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  precogs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: precogs-ai/precogs-action@v1
        with:
          api-key: ${{ secrets.PRECOGS_API_KEY }}
          severity-threshold: high
          sarif-output: precogs-results.sarif

      # Upload results to GitHub Code Scanning
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: precogs-results.sarif
```

Get your API key at [app.precogs.ai](https://app.precogs.ai).

---

## 🔍 What It Scans

| Scanner | Free | Pro | What it finds |
|---|:--:|:--:|---|
| **Secrets** | ✅ | ✅ | AWS keys, GitHub tokens, Stripe keys, private keys, DB URLs, JWT tokens, and 20+ patterns |
| **PII** | ✅ | ✅ | Email addresses, SSNs, credit card numbers, phone numbers |
| **Dependencies (SCA)** | ✅ | ✅ | Known CVEs in npm, pip, Go, Ruby, and Rust packages (via [OSV.dev](https://osv.dev)) |
| **Code (SAST)** | — | ✅ | SQL injection, XSS, command injection, path traversal, insecure crypto, and 200+ vulnerability patterns |

### Secret Detection Patterns

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens (PAT, OAuth, App)
- Google Cloud / GCP API Keys & Service Account files
- Stripe Secret & Publishable Keys (live)
- Slack Tokens & Webhook URLs
- SendGrid API Keys
- Twilio API Keys
- OpenAI API Keys
- Database Connection Strings (MongoDB, PostgreSQL, MySQL, Redis)
- Private Keys (RSA, EC, DSA, OpenSSH)
- JWT Tokens
- Generic high-entropy secrets in assignments

---

## ⚙️ Inputs

| Input | Required | Default | Description |
|---|:--:|---|---|
| `api-key` | No | `''` | Precogs API key. Required for SAST code scanning only. |
| `severity-threshold` | No | `high` | Minimum severity to fail: `low`, `medium`, `high`, `critical` |
| `scan-secrets` | No | `true` | Enable free secret/PII scanning |
| `scan-code` | No | `true` | Enable AI code scan (requires `api-key`) |
| `scan-dependencies` | No | `true` | Enable free dependency CVE scan (via OSV.dev) |
| `fail-on-findings` | No | `true` | Fail the workflow if findings meet severity threshold |
| `sarif-output` | No | `''` | Path to write SARIF file for GitHub Code Scanning |

## 📤 Outputs

| Output | Description |
|---|---|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `secrets-count` | Number of secrets/PII found |
| `report-url` | URL to full report on app.precogs.ai |
| `sarif-file` | Path to generated SARIF file |

---

## 🔗 GitHub Code Scanning Integration

Upload the SARIF output to see findings directly in your repo's **Security → Code Scanning** tab:

```yaml
- uses: precogs-ai/precogs-action@v1
  with:
    api-key: ${{ secrets.PRECOGS_API_KEY }}
    sarif-output: results.sarif

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

---

## 📊 Workflow Summary

Every run generates a summary visible in the **Actions → Run → Summary** tab:

| 🔴 Critical | 🟠 High | 🔑 Secrets | Total |
|:--:|:--:|:--:|:--:|
| 1 | 2 | 3 | 6 |

---

## 🛡️ Privacy & Security

- **Free scanning runs entirely locally** — your code never leaves the GitHub runner
- **Pro scanning** sends file contents to Precogs API over HTTPS (encrypted in transit)
- No data is stored after scanning unless you explicitly opt in
- SOC 2 compliant · [Privacy policy](https://precogs.ai/privacy)

---

## 📝 License

MIT · [Precogs.ai](https://precogs.ai)
