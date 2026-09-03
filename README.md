# Correctover CCS Security Scanner - GitHub Action

> Scan MCP configuration files for security vulnerabilities in CI

![GitHub Action](https://img.shields.io/badge/GitHub%20Action-CCS%20Scanner-blue) [![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--correctover--ccs-blue)](https://datatracker.ietf.org/doc/draft-correctover-ccs/)

---

### Verifiable artifacts behind this tool

- **Third-party interoperability** — joint assessment merged into the [EMILIA protocol](https://github.com/emiliaprotocol/emilia-protocol/pull/693)
- **66 signed conformance test vectors** — reproducible by anyone: [ccs-conformance-vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors)
- **Published methodology** — [Zenodo DOI 10.5281/zenodo.21783723](https://doi.org/10.5281/zenodo.21783723)
- **Need a human audit?** — 116-check manual audit methodology, 5-day turnaround: [Agent Output Audit](https://correctover.com/agent-audit.html)

Automatically scan your MCP configuration files on every push/PR. Get inline annotations for security issues, mapped to OWASP AISVS 1.0.

## Usage

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DSHCorrectover/correctover-scan-action@v1
        with:
          path: '.'
          fail-on-critical: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `fail-on-critical` | Fail workflow on critical issues | `true` |
| `fail-on-warning` | Fail workflow on warnings | `false` |
| `format` | Output format (text/sarif) | `text` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Overall security score (0-100) |
| `files-scanned` | Number of files scanned |
| `passed` | Passed checks |
| `warnings` | Warning-level issues |
| `failures` | Critical failures |
| `total-issues` | Total issues |
| `sarif` | SARIF format results |

## SARIF Output (for GitHub Security tab)

```yaml
- uses: DSHCorrectover/correctover-scan-action@v1
  id: scan
  with:
    format: sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sarif.json
```

## Links

- [correctover.com](https://correctover.com) — AI Agent Runtime Assurance
- [Web Scanner](https://correctover.com/scan/) — Try online
- [NPM CLI](https://www.npmjs.com/package/correctover-scan) — Local scanning
- [Conformance test vectors](https://github.com/DSHCorrectover/ccs-conformance-vectors) — 66 signed, reproducible
- [EMILIA interoperability](https://github.com/emiliaprotocol/emilia-protocol/pull/693) — merged joint assessment
- [Agent Output Audit](https://correctover.com/agent-audit.html) — 116-check manual audit, 5-day turnaround

## Manual Correctover Audit

This free automated scan covers surface-level configuration checks. A manual Correctover audit goes deeper:

- **116-check manual audit methodology** — reviews your MCP setup beyond static patterns, for misconfigurations static checks cannot catch.
- **5-day turnaround** — a written report from human reviewers.
- **Grounded in real MCP ecosystem CVEs** — checks mapped to documented, real-world vulnerabilities.

**First customers:** if we find no critical-severity issue, you pay nothing.

- Learn more: <https://dshcorrectover.github.io/agent-audit/>
- **Request a free audit:** [234114134@coze.email](mailto:234114134@coze.email?subject=Free%20audit%20scan%20summary)

---
