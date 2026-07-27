# Finding Schema

Every professional RedLens finding must include:

- `id`
- `title`
- `severity`
- `confidence`
- `affected_assets`
- `category`
- `business_impact`
- `technical_impact`
- `evidence`
- `reproduction_steps`
- `root_cause`
- `remediation`
- `validation_status`
- `references`
- `cvss`
- `cwe`
- `owasp`
- `mitre_attack` when relevant
- `retest_steps`

## Quality Rules

- No finding may rely on raw scanner output alone.
- Every critical/high finding needs reproduction evidence or a documented blocker.
- Every finding needs a business impact written for leadership.
- Every remediation must be specific enough for engineering action.
- Sensitive values must be redacted in report body and preserved only in controlled evidence artifacts when authorized.
