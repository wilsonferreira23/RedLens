# Professional Report Standard

The final RedLens report is the product. It must read like a senior consultant delivered it, not like exported scanner output.

## Required Sections

1. Cover page.
2. Confidentiality and authorization statement.
3. Executive summary.
4. Scope, constraints, and testing window.
5. Methodology aligned to mode and playbooks used.
6. Risk overview and finding summary.
7. Attack chain narrative when applicable.
8. Detailed findings.
9. Tested coverage and explicit gaps.
10. Remediation roadmap.
11. Retest checklist.
12. Appendices: tools, command log summary, artifact index, CVSS vectors, references.

## Premium Quality Bar

- Executive summary must be understandable without technical context.
- Technical findings must be reproducible.
- Evidence must be linked by artifact ID.
- Severity must explain business context, not only CVSS.
- Negative results and untested areas must be explicit.
- The report must separate confirmed findings, likely issues, observations, and accepted limitations.

## Final QA Gate

Before delivery, verify:

- All findings have evidence and remediation.
- All critical/high findings were communicated through the agreed escalation channel.
- Artifact paths exist and sensitive data is redacted.
- Redaction status is recorded for every evidence artifact.
- CVSS vectors are internally consistent.
- Similar findings have consistent severity.
- Report includes mode, scope, constraints, and residual risk.
- Retest steps are actionable.
