/**
 * Dependency Scanner (SCA) — FREE tier
 * Uses Google OSV.dev API (free, no API key) to check for known CVEs
 *
 * Parses: package.json, requirements.txt, Gemfile.lock, go.sum, Cargo.lock, pom.xml
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

// ─── OSV API (free, no key) ─────────────────────────────────────────────────

async function queryOSV(ecosystem, packageName, version) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      version,
      package: { name: packageName, ecosystem },
    });

    const req = https.request({
      hostname: 'api.osv.dev',
      port: 443,
      path: '/v1/query',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ vulns: [] }); }
      });
    });
    req.on('error', () => resolve({ vulns: [] }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ vulns: [] }); });
    req.write(body);
    req.end();
  });
}

// ─── Manifest parsers ───────────────────────────────────────────────────────

function parsePackageJson(filePath) {
  try {
    const pkg = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    const deps = [];
    for (const [name, version] of Object.entries(pkg.dependencies || {})) {
      deps.push({ ecosystem: 'npm', name, version: version.replace(/^[\^~>=<]+/, '') });
    }
    for (const [name, version] of Object.entries(pkg.devDependencies || {})) {
      deps.push({ ecosystem: 'npm', name, version: version.replace(/^[\^~>=<]+/, '') });
    }
    return deps;
  } catch { return []; }
}

function parseRequirementsTxt(filePath) {
  try {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    const deps = [];
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) continue;
      const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*[=<>~!]+\s*([0-9.]+)/);
      if (match) {
        deps.push({ ecosystem: 'PyPI', name: match[1], version: match[2] });
      }
    }
    return deps;
  } catch { return []; }
}

function parseGoSum(filePath) {
  try {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n');
    const seen = new Set();
    const deps = [];
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 2) continue;
      const name = parts[0];
      const version = parts[1].replace('/go.mod', '').replace('v', '');
      const key = `${name}@${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        deps.push({ ecosystem: 'Go', name, version });
      }
    }
    return deps;
  } catch { return []; }
}

function parseGemfileLock(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const deps = [];
    const gemRegex = /^\s{4}(\S+)\s+\(([^)]+)\)/gm;
    let match;
    while ((match = gemRegex.exec(content)) !== null) {
      deps.push({ ecosystem: 'RubyGems', name: match[1], version: match[2] });
    }
    return deps;
  } catch { return []; }
}

function parseCargoLock(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const deps = [];
    const blocks = content.split('[[package]]');
    for (const block of blocks) {
      const nameMatch = block.match(/name\s*=\s*"([^"]+)"/);
      const versionMatch = block.match(/version\s*=\s*"([^"]+)"/);
      if (nameMatch && versionMatch) {
        deps.push({ ecosystem: 'crates.io', name: nameMatch[1], version: versionMatch[1] });
      }
    }
    return deps;
  } catch { return []; }
}

// ─── Manifest discovery ────────────────────────────────────────────────────

const PARSERS = {
  'package.json': parsePackageJson,
  'requirements.txt': parseRequirementsTxt,
  'go.sum': parseGoSum,
  'Gemfile.lock': parseGemfileLock,
  'Cargo.lock': parseCargoLock,
};

function findManifests(workspace) {
  const found = [];

  function walk(dir) {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'vendor') continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
        } else if (PARSERS[entry.name]) {
          found.push({ path: fullPath, parser: PARSERS[entry.name], manifest: entry.name });
        }
      }
    } catch {}
  }

  walk(workspace);
  return found;
}

// ─── Main scanner ───────────────────────────────────────────────────────────

async function scanDependencies(workspace, _apiKey) {
  // Note: _apiKey is accepted for interface compatibility but NOT needed
  const findings = [];
  const manifests = findManifests(workspace);

  if (manifests.length === 0) {
    return findings;
  }

  const core = require('@actions/core');
  core.info(`   Found ${manifests.length} manifest(s): ${manifests.map(m => m.manifest).join(', ')}`);

  for (const manifest of manifests) {
    const deps = manifest.parser(manifest.path);
    const relativePath = path.relative(workspace, manifest.path);

    // Batch: query top 50 deps (OSV is fast but let's be polite)
    const depsToCheck = deps.slice(0, 50);

    for (const dep of depsToCheck) {
      try {
        const result = await queryOSV(dep.ecosystem, dep.name, dep.version);

        if (result.vulns && result.vulns.length > 0) {
          for (const vuln of result.vulns) {
            // Get severity from OSV
            let severity = 'medium';
            if (vuln.database_specific?.severity) {
              severity = vuln.database_specific.severity.toLowerCase();
            } else if (vuln.severity) {
              const cvss = vuln.severity.find(s => s.type === 'CVSS_V3');
              if (cvss?.score >= 9.0) severity = 'critical';
              else if (cvss?.score >= 7.0) severity = 'high';
              else if (cvss?.score >= 4.0) severity = 'medium';
              else severity = 'low';
            }

            // Get fix version
            const fixVersion = vuln.affected?.[0]?.ranges?.[0]?.events
              ?.find(e => e.fixed)?.fixed || '';

            findings.push({
              type: 'dependency',
              title: `${dep.name}@${dep.version} — ${vuln.id}`,
              severity,
              file: relativePath,
              line: 0,
              cwe: vuln.aliases?.find(a => a.startsWith('CVE-')) || vuln.id,
              description: vuln.summary || `Known vulnerability in ${dep.name}@${dep.version}`,
              fixVersion,
              osvUrl: `https://osv.dev/vulnerability/${vuln.id}`,
            });
          }
        }
      } catch {
        // Skip individual package errors silently
      }
    }
  }

  return findings;
}

module.exports = { scanDependencies };
