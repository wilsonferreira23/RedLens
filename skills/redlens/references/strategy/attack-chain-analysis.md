# Attack Chain Analysis

RedLens should identify whether individual findings combine into higher-impact attack paths.

## Chain Model

- Chain ID: `C-###`
- Objective:
- Preconditions:
- Steps:
- Findings used:
- Evidence used:
- Final impact:
- Required privileges:
- Detection opportunities:
- Remediation breakpoints:

## When To Build A Chain

Build a chain when two or more findings interact, such as:

- Information disclosure enables authentication bypass.
- Weak auth enables IDOR/BOLA data access.
- Exposed admin panel plus default credentials enables control.
- SSRF reaches cloud metadata or internal services.
- Source-code secret enables API, database, or cloud access.
- AD misconfiguration enables privilege escalation.

## Reporting Rule

If a chain impact exceeds individual finding severity, include both:

1. Individual findings with remediation.
2. A chain narrative showing how the business impact emerges.

Do not invent chains. Every step must reference evidence.
