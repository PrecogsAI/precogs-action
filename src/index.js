/**
 * Precogs GitHub Action — Entry Point
 *
 * Free tier:  Secret + PII scanning (regex + entropy, runs locally)
 * Pro tier:   SAST code scan + dependency scan (via Precogs API)
 */

const core = require('@actions/core');
const github = require('@actions/github');
const fs = require('fs');
const path = require('path');
const { scanSecrets } = require('./scanners/secrets');
const { scanCode } = require('./scanners/code');
const { scanDependencies } = require('./scanners/dependencies');
const { writeSarif } = require('./sarif');

// ─── Severity ordering ──────────────────────────────────────────────────────
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

function meetsThreshold(severity, threshold) {
  return (SEV_ORDER[severity] || 0) >= (SEV_ORDER[threshold] || 0);
}

// ─── Main ───────────────────────────────────────────────────────────────────
async function run() {
  try {
    const apiKey = core.getInput('api-key');
    const threshold = core.getInput('severity-threshold').toLowerCase();
    const scanSecretsEnabled = core.getInput('scan-secrets') === 'true';
    const scanCodeEnabled = core.getInput('scan-code') === 'true';
    const scanDepsEnabled = core.getInput('scan-dependencies') === 'true';
    const failOnFindings = core.getInput('fail-on-findings') === 'true';
    const sarifOutput = core.getInput('sarif-output');

    const workspace = process.env.GITHUB_WORKSPACE;
    const allFindings = [];

    // ── Step 1: Free secret scanning (always available) ──
    if (scanSecretsEnabled) {
      core.info('🔍 Scanning for secrets and PII (free, runs locally)...');
      const secretFindings = await scanSecrets(workspace);
      allFindings.push(...secretFindings);
      core.info(`   Found ${secretFindings.length} secret/PII issue(s)`);
    }

    // ── Step 2: SAST code scan (requires API key) ──
    if (scanCodeEnabled) {
      if (!apiKey) {
        core.info('⏭️  Skipping code scan (no API key). Get one at https://app.precogs.ai');
      } else {
        core.info('🔬 Running AI code scan (SAST)...');
        const codeFindings = await scanCode(workspace, apiKey);
        allFindings.push(...codeFindings);
        core.info(`   Found ${codeFindings.length} code vulnerability(ies)`);
      }
    }

    // ── Step 3: Dependency scan (FREE — uses OSV.dev, no API key needed) ──
    if (scanDepsEnabled) {
      core.info('📦 Scanning dependencies for known CVEs (free, via OSV.dev)...');
      const depFindings = await scanDependencies(workspace);
      allFindings.push(...depFindings);
      core.info(`   Found ${depFindings.length} dependency issue(s)`);
    }

    // ── Results ──
    const criticals = allFindings.filter(f => f.severity === 'critical').length;
    const highs = allFindings.filter(f => f.severity === 'high').length;
    const secrets = allFindings.filter(f => f.type === 'secret' || f.type === 'pii').length;

    core.setOutput('findings-count', String(allFindings.length));
    core.setOutput('critical-count', String(criticals));
    core.setOutput('high-count', String(highs));
    core.setOutput('secrets-count', String(secrets));

    if (apiKey) {
      core.setOutput('report-url', `https://app.precogs.ai/reports/ci/${github.context.repo.owner}/${github.context.repo.repo}/${github.context.sha.slice(0, 7)}`);
    }

    // ── SARIF output (for GitHub Code Scanning) ──
    if (sarifOutput && allFindings.length > 0) {
      const sarifPath = path.resolve(sarifOutput);
      writeSarif(allFindings, sarifPath);
      core.setOutput('sarif-file', sarifPath);
      core.info(`📄 SARIF written to ${sarifPath}`);
    }

    // ── Summary ──
    core.info('');
    core.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    core.info(`⚡ Precogs scan complete — ${allFindings.length} finding(s)`);
    core.info(`   🔴 Critical: ${criticals}  🟠 High: ${highs}  🔑 Secrets: ${secrets}`);
    core.info('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    // Print each finding
    for (const f of allFindings) {
      const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : '🔵';
      core.info(`${icon} [${f.severity.toUpperCase()}] ${f.title} — ${f.file}:${f.line || '?'}`);
    }

    // ── GitHub Actions summary (shows in workflow run UI) ──
    await core.summary
      .addHeading('⚡ Precogs Security Scan', 2)
      .addTable([
        [{ data: '🔴 Critical', header: true }, { data: '🟠 High', header: true }, { data: '🔑 Secrets', header: true }, { data: 'Total', header: true }],
        [String(criticals), String(highs), String(secrets), String(allFindings.length)],
      ])
      .addLink('View full report on Precogs', `https://app.precogs.ai`)
      .write();

    // ── Fail check if threshold met ──
    if (failOnFindings) {
      const blockingFindings = allFindings.filter(f => meetsThreshold(f.severity, threshold));
      if (blockingFindings.length > 0) {
        core.setFailed(`❌ ${blockingFindings.length} finding(s) at or above '${threshold}' severity. See details above.`);
      }
    }

  } catch (error) {
    core.setFailed(`Precogs scan error: ${error.message}`);
  }
}

run();
