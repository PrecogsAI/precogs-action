/**
 * SARIF Output — Integrates with GitHub Code Scanning
 *
 * When users upload this SARIF file, findings appear in the
 * Security → Code Scanning tab on GitHub.
 */

const fs = require('fs');

function writeSarif(findings, outputPath) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Precogs',
          organization: 'Precogs AI',
          semanticVersion: '1.0.0',
          informationUri: 'https://precogs.ai',
          rules: [],
        },
      },
      results: [],
    }],
  };

  const rulesMap = new Map();

  for (const finding of findings) {
    const ruleId = finding.cwe || finding.type || 'precogs-finding';

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description || finding.title },
        helpUri: `https://precogs.ai/docs/rules/${ruleId}`,
        defaultConfiguration: {
          level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning',
        },
      });
    }

    sarif.runs[0].results.push({
      ruleId,
      level: finding.severity === 'critical' || finding.severity === 'high' ? 'error' : 'warning',
      message: { text: finding.description || finding.title },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.file },
          region: { startLine: finding.line || 1 },
        },
      }],
    });
  }

  sarif.runs[0].tool.driver.rules = Array.from(rulesMap.values());
  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2));
}

module.exports = { writeSarif };
