/**
 * Code Scanner (SAST) — PRO tier (requires API key)
 * Calls Precogs API for AI-powered vulnerability detection
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const API_BASE = 'https://api.precogs.ai/api/v1';

async function apiPost(endpoint, data, apiKey) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify(data);
    const url = new URL(`${API_BASE}${endpoint}`);

    const req = https.request({
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let responseData = '';
      res.on('data', chunk => responseData += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(responseData));
        } catch {
          resolve({ error: responseData });
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(90000, () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

async function scanCode(workspace, apiKey) {
  const findings = [];

  try {
    const result = await apiPost('/scan/ci', {
      workspace_path: workspace,
      repository: process.env.GITHUB_REPOSITORY,
      sha: process.env.GITHUB_SHA,
      ref: process.env.GITHUB_REF,
    }, apiKey);

    if (result.vulnerabilities && Array.isArray(result.vulnerabilities)) {
      for (const vuln of result.vulnerabilities) {
        findings.push({
          type: 'code',
          title: vuln.vulnerabilityType || vuln.title || 'Code Vulnerability',
          severity: (vuln.severity || 'medium').toLowerCase(),
          file: vuln.file_path || vuln.file || '',
          line: vuln.line || vuln.startLine || 0,
          cwe: vuln.cwe || '',
          owasp: vuln.owasp || '',
          description: vuln.description || '',
          fixSuggestion: vuln.fixSuggestion || vuln.fixedCode || '',
        });
      }
    }
  } catch (err) {
    // Non-fatal: API might be unreachable
    const core = require('@actions/core');
    core.warning(`Code scan API error: ${err.message}`);
  }

  return findings;
}

module.exports = { scanCode };
