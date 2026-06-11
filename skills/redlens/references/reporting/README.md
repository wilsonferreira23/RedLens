# Reporting

The penetration test report is the final deliverable; its quality directly affects how clients perceive the value of the engagement. A good report addresses two audiences: management (risk summary) and the technical team (reproduction steps).

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Web page screenshots | `gowitness` | Use `eyewitness` when manual screenshot judgment is needed |
| Document format conversion | `pandoc` | — |
| Report structure | `tools/report-template.md` | — |

---

## Screenshots and Documentation

For bulk web service screenshots, use `gowitness` or `eyewitness` from the information gathering category.

---

## Document Processing

**[pandoc](tools/pandoc.md)** — Document format conversion  
Converts Markdown to Word/PDF/HTML and other formats. Can be used with report templates to batch-generate professional reports.  

---

## Report Templates and Standards

**[report-template](tools/report-template.md)** — Standard report template  
Includes a complete penetration test report structure template, risk level definitions (CVSS scoring), and vulnerability description standards.  

---

## Report Structure

A professional penetration test report should include:

1. **Executive Summary** — high-level risk overview for management; no technical jargon
2. **Scope and Methodology** — target assets, testing window, approach, and any limitations
3. **Findings** — each finding with title, severity, description, evidence (screenshots/commands), affected assets, and remediation
4. **Remediation Summary** — prioritized action items grouped by severity
5. **Appendix** — raw tool output, full scan results, wordlists used, and environment details

---

## Severity Framework

Use CVSS v3.1 or v4.0 for consistent severity scoring:

| Rating | CVSS Score | Description |
|--------|-----------|-------------|
| Critical | 9.0 - 10.0 | Immediate exploitation risk, full system compromise |
| High | 7.0 - 8.9 | Significant impact, likely exploitable |
| Medium | 4.0 - 6.9 | Moderate impact, requires specific conditions |
| Low | 0.1 - 3.9 | Minor impact, informational or defense-in-depth |

Reference `tools/report-template.md` for the full template with CVSS scoring guidelines.

---

## Quick Reporting Workflow

```bash
# 1. Record findings in real time to markdown files during testing
# 2. Use gowitness to screenshot and archive discovered web services
# 3. After testing, organize findings and add CVSS scores
# 4. Convert to Word/PDF with pandoc and deliver

# Simple approach:
# Record directly in Markdown and convert to PDF with pandoc
# Requires wkhtmltopdf: sudo apt install wkhtmltopdf
pandoc report.md -o report.pdf --pdf-engine=wkhtmltopdf
```

---

## Playbook

For a full scenario workflow covering report generation phases and quality gates, see `../playbooks/reporting-workflow.md`.

---

## Official References

- [Kali Tools](https://www.kali.org/tools/all-tools/)
