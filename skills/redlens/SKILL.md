---
name: redlens
description: RedLens executes authorized Kali Linux penetration testing workflows with strict scope, risk gates, evidence capture, and reporting. Use for approved security assessments involving recon, web/API testing, network enumeration, vulnerability validation, password audits, cloud-native checks, wireless, forensics, or post-exploitation planning.
license: MIT
compatibility: codex, claude-code, opencode, agent-skills
metadata:
  category: security
  audience: authorized-security-testers
  risk: high
---

# RedLens

## Non-Negotiable Safety Rules

1. Confirm explicit authorization before scanning, probing, exploitation, brute forcing, credential testing, or post-exploitation.
2. Treat scope as binding: hosts, domains, ports, accounts, time windows, and allowed techniques are limits, not suggestions.
3. Ask for a second explicit approval before high-risk actions: exploitation, brute forcing, credential spraying, phishing, NTLM relay, wireless attacks, persistence, data exfiltration, destructive checks, DoS-like checks, or intrusive scanners.
4. Do not attack third-party, critical infrastructure, production systems, or accounts outside the authorized scope.
5. Prefer evidence-preserving, minimally invasive validation. Stop when impact is proven enough to report.

## Start Every Assessment

1. Identify target type: URL, domain, IP, CIDR, repository, mobile app, wireless SSID, artifact, or account set.
2. Confirm authorization, scope, constraints, test type, rate limits, lockout policy, and reporting format.
3. Select assessment mode:
   - `quick`: fast triage with mandatory coverage and explicit gaps.
   - `standard`: default mode; broad, evidence-driven coverage that should feel close to deep without the longest-running checks.
   - `deep`: exhaustive mode with expanded enumeration, chaining, cross-validation, and comprehensive reporting.
4. Read `references/playbooks/assessment-modes.md` and apply its required coverage before choosing individual tools.
5. Select execution environment:
   - Local Kali: use direct commands.
   - SSH Kali: use `ssh` and `scp`.
   - Docker Kali: use persistent `kali-pentest` container.
6. Create state directory: `/tmp/kali-pentest-state/<safe-target-name>/`.
7. Record scope, approvals, assessment mode, commands, evidence paths, findings, gaps, and deferred actions in state files.
8. Read `references/strategy/operator-brain.md` and use the hypothesis loop before selecting tools.

## Environment References

- Local mode: `references/environment/local-mode.md`
- SSH/server mode: `references/environment/server-mode.md`
- Docker mode: `references/environment/docker-mode.md`
- Persistent Docker container: `references/environment/docker-mode-persistent-container.md`
- Docker networking: `references/environment/docker-mode-networking.md`
- State files: `references/environment/state-files.md`
- Structured state schema: `references/environment/state-schema.md`

## Browser Automation

Use CloakBrowser for browser-dependent web testing, CDN challenge handling, and anti-bot protected pages. Do not default to Puppeteer, Playwright, or regular headless Chromium when the target returns JS challenges, CAPTCHA pages, "Checking your browser" screens, Cloudflare Turnstile, or similar anti-bot flows.

Read `references/web/tools/cloakbrowser.md` before browser automation and `references/playbooks/web-application.md` for the web assessment flow.

## Playbook Routing

Read `references/playbooks/assessment-modes.md` and `references/playbooks/README.md`, then load only the relevant playbook:

- Operator brain: `references/strategy/operator-brain.md`
- Attack chain analysis: `references/strategy/attack-chain-analysis.md`
- Coverage gates: `references/strategy/coverage-gates.md`
- Assessment modes: `references/playbooks/assessment-modes.md`
- Web application: `references/playbooks/web-application.md`
- CloakBrowser: `references/web/tools/cloakbrowser.md`
- API security: `references/playbooks/api-security.md`
- External attack surface: `references/playbooks/external-attack-surface.md`
- Internal network: `references/playbooks/internal-network.md`
- Active Directory: `references/playbooks/active-directory.md`
- Cloud-native: `references/playbooks/cloud-native-assessment.md`
- Mobile app: `references/playbooks/mobile-application.md`
- Wireless: `references/playbooks/wireless-assessment.md`
- Source code audit: `references/playbooks/source-code-audit.md`
- Forensics triage: `references/playbooks/forensics-triage.md`
- Password audit: `references/playbooks/password-audit.md`
- Post-exploitation: `references/playbooks/post-exploitation.md`
- Reporting: `references/playbooks/reporting-workflow.md`
- Professional report standard: `references/reporting/professional-report-standard.md`

## Operating Loop

1. Plan the next safe action from the selected mode contract and playbook.
2. Run the minimum command needed for that step in the selected environment.
3. Save raw output to a file instead of flooding context.
4. Extract only relevant evidence into the state directory.
5. Update findings with severity, affected asset, reproduction steps, impact, evidence, and remediation.
6. Track required coverage, skipped checks, and why they were skipped.
7. Reassess risk before escalating technique or intensity.

## Reporting

Produce an executive summary and technical report with:

- Scope and authorization summary.
- Methodology and constraints.
- Confirmed findings only, separated from observations.
- Evidence references and reproduction steps.
- Business impact.
- Remediation guidance.
- Retest checklist.
- Attack chain narratives when multiple findings combine into higher impact.

Use `references/playbooks/reporting-workflow.md` for structure.
Use `references/reporting/professional-report-standard.md` and `references/reporting/finding-schema.md` as the professional deliverable contract.
