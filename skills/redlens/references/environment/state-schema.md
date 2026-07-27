# State Schema

Structured state keeps RedLens resumable and makes reporting deterministic.

## Directory Layout

```text
/tmp/kali-pentest-state/<target>/
  engagement.json
  target_model.json
  hypotheses.jsonl
  findings.jsonl
  evidence_manifest.jsonl
  command_log.jsonl
  coverage.json
  decisions.jsonl
  report/
```

## `engagement.json`

Required fields:

- `target_name`
- `assessment_mode`: `quick`, `standard`, or `deep`
- `target_type`
- `authorization_status`: `confirmed`
- `scope`
- `constraints`
- `risk_gates`
- `created_at`
- `updated_at`

## `findings.jsonl`

One JSON object per confirmed or likely finding:

- `id`
- `title`
- `severity`
- `confidence`
- `affected_assets`
- `category`
- `cwe`
- `owasp`
- `mitre_attack`
- `cvss`
- `business_impact`
- `technical_impact`
- `evidence_refs`
- `reproduction_steps`
- `remediation`
- `validation_status`
- `mode_found`

## `evidence_manifest.jsonl`

One JSON object per artifact:

- `id`
- `finding_id`
- `artifact_type`
- `path`
- `source_environment`
- `command_id`
- `timestamp`
- `sha256`
- `redaction_status`
- `notes`

## Rule

Text summaries may exist, but structured JSON/JSONL is the source of truth for reporting.
