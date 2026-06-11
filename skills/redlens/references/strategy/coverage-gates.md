# Coverage Gates

Coverage gates prevent RedLens from ending an assessment with hidden blind spots.

## Universal Gates

- Authorization recorded.
- Mode selected.
- Scope and exclusions recorded.
- Target model initialized.
- Required playbook selected.
- Evidence directory exists.
- Command log has entries for executed tools.
- Coverage gaps are explicit.
- Findings are classified as confirmed, likely, observation, false-positive, blocked, or not-applicable.
- Reporting handoff is complete.

## Negative Result Rule

Every tested asset, service, endpoint, identity boundary, or workflow must have one of:

- a finding,
- a negative result,
- a blocked status,
- or an explicit out-of-scope decision.

## Stop Rule

Do not say an assessment is complete until all required coverage gates for the selected mode and playbook are satisfied or documented as accepted gaps.
