/**
 * Correctover CCS Security Scanner - GitHub Action
 * Scans MCP configuration files in CI and reports issues as annotations
 */

const core = require('@actions/core');
const fs = require('fs');
const path = require('path');
const { runScan, parseConfig, KNOWN_CONFIG_PATHS } = require('./core/scanner');
const { recordCall, getUpgradeMessage } = require('./core/license');

// Manual audit CTA (verbatim; printed to job summary tail and action log tail)
const AUDIT_LANDING_URL = 'https://dshcorrectover.github.io/agent-audit/';
const AUDIT_CTA = `Free automated scan covers surface-level checks. A manual Correctover audit goes deeper: 116 semantic intent rules, 5-day turnaround, findings grounded in real MCP ecosystem CVEs. First customers: if we find no critical-severity issue, you pay nothing. → ${AUDIT_LANDING_URL}`;

function findConfigFiles(dir) {
  const found = [];
  for (const relPath of KNOWN_CONFIG_PATHS) {
    const fullPath = path.resolve(dir, relPath);
    if (fs.existsSync(fullPath)) {
      found.push(fullPath);
    }
  }
  // Recursively search for mcp config files
  function walkDir(currentDir) {
    try {
      const entries = fs.readdirSync(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === 'node_modules' || entry.name === '.git') continue;
        const fullPath = path.join(currentDir, entry.name);
        if (entry.isDirectory()) {
          walkDir(fullPath);
        } else if (entry.isFile() && /mcp[_-]?.*\.(json|yaml|yml)$/.test(entry.name)) {
          if (!found.includes(fullPath)) found.push(fullPath);
        }
      }
    } catch (e) {}
  }
  walkDir(dir);
  return found;
}

function severityToLevel(severity) {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'warning';
    case 'medium': return 'warning';
    default: return 'notice';
  }
}

async function run() {
  try {
    const scanPath = core.getInput('path') || process.cwd();
    const failOnCritical = core.getInput('fail-on-critical') === 'true';
    const failOnWarning = core.getInput('fail-on-warning') === 'true';
    const outputFormat = core.getInput('format') || 'text';

    // License check
    const licStatus = recordCall('correctover-scan-action');
    if (!licStatus.authorized) {
      core.setFailed('Free tier limit reached (50 scans/day). Upgrade: https://correctover.com/checkout');
      return;
    }
    if (licStatus.tier === 'free') {
      core.info(`Free tier: ${licStatus.calls_remaining} scans remaining today`);
    }
    core.info(`🔍 Correctover CCS Security Scanner v1.1.0`);
    core.info(`Scanning: ${scanPath}`);
    core.info('');

    const filesToScan = findConfigFiles(scanPath);

    if (filesToScan.length === 0) {
      core.info('⚠️ No MCP configuration files found.');
      core.info(`Searched for: ${KNOWN_CONFIG_PATHS.join(', ')}`);
      core.setOutput('files-scanned', 0);
      core.setOutput('total-issues', 0);

      // Manual audit CTA (job summary + action log)
      core.info('');
      core.info(AUDIT_CTA);
      try {
        await core.summary.addRaw(`\n\n---\n${AUDIT_CTA}`).write();
      } catch (e) {}
      return;
    }

    core.info(`Found ${filesToScan.length} config file(s)\n`);

    let totalPass = 0, totalWarn = 0, totalFail = 0, totalInfo = 0;
    let hasCritical = false;
    let hasWarning = false;

    for (const fp of filesToScan) {
      try {
        const content = fs.readFileSync(fp, 'utf-8');
        const config = parseConfig(content, fp);
        const { results, stats } = runScan(config);
        const relPath = path.relative(scanPath, fp) || fp;

        core.info(`📄 ${relPath}`);
        core.info(`   Score: ${stats.score}/100 | ✓${stats.pass} ⚠${stats.warn} ✗${stats.fail} ℹ${stats.info}`);

        totalPass += stats.pass;
        totalWarn += stats.warn;
        totalFail += stats.fail;
        totalInfo += stats.info;

        // Create GitHub annotations for issues
        for (const r of results) {
          if (r.status === 'fail') {
            hasCritical = true;
            core.error(`${r.name} [${r.aisvs}]: ${r.fix}`, {
              file: relPath,
              title: `CCS Security: ${r.category}`
            });
          } else if (r.status === 'warn') {
            hasWarning = true;
            core.warning(`${r.name} [${r.aisvs}]: ${r.fix}`, {
              file: relPath,
              title: `CCS Security: ${r.category}`
            });
          }
        }

        // SARIF output
        if (outputFormat === 'sarif') {
          const sarif = {
            version: '2.1.0',
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            runs: [{
              tool: {
                driver: {
                  name: 'correctover-scan-action',
                  version: '1.0.0',
                  informationUri: 'https://correctover.com',
                  rules: results.map(r => ({
                    id: r.id,
                    name: r.name,
                    shortDescription: { text: `${r.category}: ${r.name}` },
                    properties: { aisvs: r.aisvs, severity: r.severity }
                  }))
                }
              },
              results: results.filter(r => r.status === 'fail' || r.status === 'warn').map(r => ({
                ruleId: r.id,
                level: severityToLevel(r.severity),
                message: { text: r.fix },
                locations: [{ physicalLocation: { artifactLocation: { uri: relPath } } }]
              }))
            }]
          };
          core.setOutput('sarif', JSON.stringify(sarif, null, 2));
        }

      } catch (e) {
        core.error(`Error scanning ${fp}: ${e.message}`);
      }
    }

    // Set outputs
    const totalIssues = totalFail + totalWarn;
    const overallScore = Math.round(((totalPass * 10 + totalWarn * 5 + totalInfo * 7) / ((totalPass + totalWarn + totalFail + totalInfo) * 10)) * 100);

    core.setOutput('files-scanned', filesToScan.length);
    core.setOutput('score', overallScore);
    core.setOutput('passed', totalPass);
    core.setOutput('warnings', totalWarn);
    core.setOutput('failures', totalFail);
    core.setOutput('total-issues', totalIssues);

    // Summary
    core.startGroup('Security Scan Summary');
    core.info(`Files scanned: ${filesToScan.length}`);
    core.info(`Overall score: ${overallScore}/100`);
    core.info(`✅ Passed: ${totalPass}`);
    core.info(`⚠️  Warnings: ${totalWarn}`);
    core.info(`❌ Failures: ${totalFail}`);
    core.info(`ℹ️  Info: ${totalInfo}`);
    core.endGroup();

    // Add job summary
    const proCta = overallScore < 60 || totalFail > 0
      ? `\n\n---\n**⚡ Need a formal compliance report?** [CCS Pro](https://correctover.com/checkout) generates audit reports, compliance certificates, and team dashboards. Enterprise includes runtime SDK + Token guarantee.`
      : `\n\n---\n**✅ Nice score!** Get a formal compliance certificate with [CCS Pro](https://correctover.com/checkout) — audit reports, team dashboard, SOC 2 ready.`;
    
    await core.summary
      .addHeading('🔒 CCS Security Scan Results')
      .addTable([
        [
          { data: 'Metric', header: true },
          { data: 'Value', header: true }
        ],
        ['Files Scanned', String(filesToScan.length)],
        ['Security Score', `${overallScore}/100`],
        ['✅ Passed', String(totalPass)],
        ['⚠️ Warnings', String(totalWarn)],
        ['❌ Failures', String(totalFail)],
        ['ℹ️ Info', String(totalInfo)]
      ])
      .addLink('Powered by Correctover', 'https://correctover.com')
      .addRaw(proCta)
      .addRaw(`\n\n---\n${AUDIT_CTA}`)
      .write();

    // Manual audit CTA (action log tail)
    core.info('');
    core.info(AUDIT_CTA);

    // Fail if configured
    if (failOnCritical && hasCritical) {
      core.setFailed(`Critical security issues found: ${totalFail} failure(s)`);
    } else if (failOnWarning && (hasCritical || hasWarning)) {
      core.setFailed(`Security issues found: ${totalIssues} issue(s)`);
    }

  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

run();
