# Assessment Modes

RedLens has three assessment modes. They are not quality levels. They are time, depth, and evidence profiles. Every mode must preserve authorization, scope, risk gates, evidence capture, and reporting.

If the user does not choose a mode, use `standard`.

## Mode Contract

| Mode | Purpose | Default Use | Must Produce |
| --- | --- | --- | --- |
| `quick` | Fast signal without blind spots | Triage, first pass, time-boxed checks, pre-sales validation, CI-style sanity checks | Scope summary, live assets, key technologies, top risks, evidence links, untested gaps, next mode recommendation |
| `standard` | High-confidence assessment without deep-only runtime | Normal authorized assessment, most web/API/network targets, first professional report | Asset inventory, endpoint/service inventory, prioritized findings, negative coverage notes, reproduction steps, remediation, retest checklist |
| `deep` | Exhaustive validation and chaining | High-value target, post-incident review, mature security program, explicit deep authorization | Standard outputs plus expanded enumeration, chained findings, cross-tool validation, screenshots/artifacts, attack paths, full technical report |

## Non-Negotiable Rules

1. `quick` cannot mean "run one scanner and stop." It must touch every mandatory coverage category for the target type.
2. `standard` is the default and must be close to `deep` in reasoning quality. It reduces runtime and breadth, not diligence.
3. `deep` adds exhaustive enumeration, repeated validation, chaining, and long-running tools. It does not bypass risk gates.
4. Every mode must list skipped checks and explain whether they were out of scope, too risky, blocked, unsupported by the environment, or deferred to a deeper mode.
5. Escalate from `quick` to `standard`, or `standard` to `deep`, when findings suggest hidden attack surface, authentication complexity, exposed admin surfaces, sensitive data, unusual infrastructure, or inconsistent scanner results.

Apply `../strategy/coverage-gates.md` before ending any mode.

## Coverage by Target Type

### Web Application

| Coverage | Quick | Standard | Deep |
| --- | --- | --- | --- |
| Reachability and fingerprinting | Required | Required | Required with cross-checks |
| TLS/security headers | Required | Required | Required with full TLS analysis |
| Crawl and endpoint inventory | Shallow crawl plus JS URL extraction | Crawl, JS extraction, historical URLs, parameter discovery | Multiple crawlers, historical sources, content diffing, hidden route hunting |
| Auth surface review | Identify login, reset, signup, SSO, session handling | Test common auth flaws within scope | Deep auth logic, token lifecycle, privilege boundaries, session fixation paths |
| Access control | Sample IDOR/BOLA probes on obvious object IDs | Systematic object, role, and tenant boundary checks | Chained authorization paths and multi-account abuse cases |
| Injection and input handling | High-signal reflected/stored inputs only | SQLi, XSS, SSTI, command/path traversal where applicable | Expanded payload families, WAF-aware validation, second-order checks |
| Business logic | Identify payment, plan, invite, admin, upload, webhook flows | Test critical flows for bypasses | Model abuse paths and chained impact |
| Reporting | Short triage report with gaps | Professional technical report | Comprehensive report with attack paths |

### API

| Coverage | Quick | Standard | Deep |
| --- | --- | --- | --- |
| Spec discovery | Detect OpenAPI/GraphQL/gRPC hints | Build endpoint and schema inventory | Reconstruct schema from traffic, JS, docs, and fuzzing |
| Auth and tokens | Identify auth scheme and obvious token risks | Validate token handling, role boundaries, tenant isolation | Token lifecycle, signing edge cases, replay, refresh, privilege chains |
| Object authorization | Sample object ID swaps | Systematic BOLA/BFLA matrix | Multi-role, multi-tenant, chained object graph testing |
| Input validation | High-risk params | Fuzz high-value parameters | Deep fuzzing with rate controls and semantic payloads |
| Rate limits and abuse | Observe exposed limits | Test authorized abuse cases carefully | Model cost, quota, workflow, and automation abuse |

### Network or External Attack Surface

| Coverage | Quick | Standard | Deep |
| --- | --- | --- | --- |
| Asset discovery | Known targets plus fast DNS/port pass | Expanded DNS, HTTP probing, service enumeration | Multiple discovery sources and recursive expansion |
| Service validation | Top ports and banners | Version checks, safe scripts, screenshots | Comprehensive ports, UDP where authorized, cross-tool validation |
| Vulnerability checks | Critical/high templates only | Critical/high/medium with manual validation | Broader templates, OpenVAS/GVM where appropriate, exploitability analysis |
| Credential/default checks | Only if explicitly allowed | Lockout-aware defaults and known creds | Deeper password audit playbook with approval |

### Source Code or Repository

| Coverage | Quick | Standard | Deep |
| --- | --- | --- | --- |
| Secrets | High-signal secret scan | Full secret scan and validation guidance | History, branches, artifacts, CI/CD variables where authorized |
| Dependency risk | Manifest review | SCA plus reachable-risk notes | Exploitability, transitive risk, build/deploy chain |
| Security controls | Identify auth, storage, crypto, dangerous sinks | Trace critical flows | Data-flow review and attack path modeling |

## Mode-Specific Execution Rules

### Quick

- Time-box aggressively, but do not skip mandatory categories.
- Prefer fast, high-signal tools and manual review of the most exposed flows.
- Stop with a useful triage result, not a vague "no issues found."
- Output must include: "What was tested", "What was not tested", "Top risks", and "Recommended next mode."

### Standard

- Treat this as the professional default.
- Build a real inventory before testing: assets, endpoints, parameters, roles, and trust boundaries.
- Validate findings manually enough to reduce false positives.
- Use selective automation, not single-tool scanning.
- Output must be good enough for engineering remediation without needing a deep rerun.

### Deep

- Expand enumeration sources and repeat important checks with independent tools.
- Chain findings across auth, access control, business logic, storage, infrastructure, and third-party services.
- Preserve artifacts: raw outputs, screenshots, requests/responses, PoCs, hashes, and timeline notes.
- Produce executive and technical reporting with attack paths and retest steps.

## Escalation Triggers

Recommend a deeper mode when any of these appear:

- Authentication or authorization is complex, custom, multi-tenant, or role-heavy.
- Public JS exposes hidden endpoints, keys, admin paths, feature flags, or internal domains.
- Quick checks find one confirmed high-risk issue.
- Scanner output conflicts with manual evidence.
- Sensitive data, payment logic, file upload, webhooks, SSO, or admin functions are in scope.
- Docker mode limits raw sockets, same-LAN visibility, browser realism, GPU cracking, or service-backed tools.

## Report Language

Do not say "secure" after `quick` or `standard`. Use precise statements:

- "No confirmed findings in the tested coverage."
- "The following areas were not tested in this mode."
- "A deeper assessment is recommended because..."
