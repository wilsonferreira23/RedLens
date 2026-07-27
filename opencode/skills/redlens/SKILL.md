---
name: redlens
description: RedLens executes authorized autonomous web and API assessments with persistent coverage, evidence capture, and reporting.
license: MIT
compatibility: codex, claude-code, opencode, agent-skills
metadata:
  category: security
  audience: authorized-security-testers
  risk: high
---

# RedLens

## Autonomous Web Contract

RedLens is the only public pentest agent. Kali, Decepticon, and browser automation
are internal tools, not alternative agents.

Every operation starts through:

```text
redlensctl init --target <URL> --authorized
```

Optional init flags: `--environment`, `--mode`, `--max-rps`, `--rate-window`,
`--categories`, `--impact-level`, `--accounts`, `--credentials-available`,
`--destructive-authorized`, `--prohibited-techniques`, `--report-format`.

The command must succeed before any network request.

Store all state and artifacts under:

```text
runs/<run-id>/ under the configured RedLens data directory.
```

The agent specializes in web applications and APIs. Do not route to network,
wireless, Active Directory, mobile, forensics, or post-exploitation playbooks.

## Non-Negotiable Safety Rules

1. Confirm authorization before scanning or testing.
2. Store all operational data on ADATA volume.
3. Apply scope validation to every request URL, redirect, and browser final URL.
4. Never claim high confidence or `claim_allowed: true` without a valid benchmark.

## Start Every Assessment

1. Identify the target URL.
2. Before any network action, obtain explicit answers for authorization,
   test credentials, environment, destructive permission, assessment mode,
   prohibited techniques, and report format. Do not infer defaults.
3. **Preflight runs automatically** — after the questionnaire and before `init`,
   the agent executes `redlensctl preflight` (diagnostico + auto-heal) to verify:
   - ADATA mount, Docker, Kali container, CloakBrowser
   - All wrappers, symlinks, .venv
   - Auto-heals broken wrappers, orphan symlinks, container state, PYTHONPATH
   If preflight fails, `init` is blocked until issues are resolved.
4. Create state with `redlensctl init`; never create an ad-hoc state directory.
5. Record inventory, hypotheses, tasks, evidence paths, findings, and deferred actions.

## Automatic Credential Provisioning (Temp Email)

When the user reports `--credentials-available no` but assessment reveals
that self-registration is open (`disable_signup: false` or equivalent),
RedLens **must automatically provision test credentials** using a
temporary email service instead of stopping at the `blocked` gate.

### Workflow

1. **Check signup viability** via the auth provider's settings endpoint
   (e.g., Supabase `/auth/v1/settings`):

   - `disable_signup: false` → signup is possible
   - `mailer_autoconfirm: true` → signup is immediate (no email needed)
   - `mailer_autoconfirm: false` → email confirmation link will be sent

2. **Create a disposable inbox** using a temp email API:

   | Service | API | Domain example |
   |---|---|---|
   | mail.tm | `POST /accounts` | `@web-library.net` |
   | Guerrilla Mail | `POST /email.php` | `@guerrillamail.com` |

   ```bash
   # mail.tm
   DOMAINS=$(curl -s https://api.mail.tm/domains)
   DOMAIN=$(echo "$DOMAINS" | python3 -c "import sys,json; print(json.load(sys.stdin)['hydra:member'][0]['domain'])")
   INBOX=$(curl -s -X POST https://api.mail.tm/accounts \
     -H "Content-Type: application/json" \
     -d "{\"address\":\"redlens-\$(date +%s)@${DOMAIN}\",\"password\":\"RedLens@2024\"}")
   TOKEN=$(curl -s -X POST https://api.mail.tm/token \
     -H "Content-Type: application/json" \
     -d "{\"address\":\"\$(echo \$INBOX | python3 -c ...)\",\"password\":\"RedLens@2024\"}")
   ```

3. **Register the account** on the target using the temp email + strong
   password:

   ```bash
   curl -s -X POST "$AUTH_URL/signup" \
     -H "apikey: $ANON_KEY" \
     -d "{\"email\":\"${TEMP_EMAIL}\",\"password\":\"${PASSWORD}\"}"
   ```

4. **If `mailer_autoconfirm: true`**: login immediately with the same
   credentials and proceed with authenticated tests.

5. **If `mailer_autoconfirm: false`**: poll the temp inbox for the
   confirmation email (up to 60s, polling every 5s):

   ```bash
   for i in $(seq 1 12); do
     sleep 5
     MSGS=$(curl -s -H "Authorization: Bearer $TOKEN" \
       "https://api.mail.tm/messages?page=1")
     CONFIRM_LINK=$(echo "$MSGS" | python3 -c "
       import sys,json,re; msgs=json.load(sys.stdin)
       for m in msgs.get('hydra:member', []):
         body = m.get('textBody', '') or ''
         links = re.findall(r'https?://\S+', body)
         confirm = [l for l in links if 'token' in l or 'confirm' in l or 'verify' in l]
         if confirm: print(confirm[0]); break
     ")
     [ -n "$CONFIRM_LINK" ] && break
   done
   ```

   Extract the confirmation token from the link and call the verify
   endpoint:

   ```bash
   curl -s -X POST "$AUTH_URL/verify" \
     -H "apikey: $ANON_KEY" \
     -d "{\"type\":\"signup\",\"token\":\"${TOKEN}\",\"email\":\"${TEMP_EMAIL}\"}"
   ```

6. **Login** with the confirmed credentials to obtain a session token.

7. **Register the identity** in the operation state:

   ```bash
   redlensctl add-identity --run <run-id> --role self-registered \
     --label "Conta criada via temp email (mail.tm)"
   ```

   Never store the actual password or temp email in state — only
   the role label and that it was provisioned.

8. **Clean up** the temp inbox at the end of the operation:

   ```bash
   curl -s -X DELETE "https://api.mail.tm/accounts/$ACCOUNT_ID" \
     -H "Authorization: Bearer $TOKEN"
   ```

9. **If all signup paths fail** (rate limit, validation, or no signup
   available), record the blocker and continue with anonymous tests:

## Operating Loop

1. Plan the next action from the selected mode contract and playbook.
2. Run the minimum command needed for that step.
3. Save raw output to a file instead of flooding context.
4. Extract only relevant evidence into the state directory.
5. Update findings with severity, affected asset, reproduction steps, impact, evidence, and remediation.
6. Track required coverage, skipped checks, and why they were skipped.
7. Reassess risk before escalating technique or intensity.
8. Record every applicable coverage category with `redlensctl record-coverage`.
9. Close or defer every task explicitly and clean resources created for testing.
10. Run `redlensctl quality-gate` before claiming completion.
11. Generate deterministic reports with `redlensctl report`.

## Internal Delegation

RedLens is the sole orchestrator. It may delegate registered, independent
tasks to `redlens-surface-mapper`, `redlens-identity-access`,
`redlens-server-side`, `redlens-workflow-abuse`, and
`redlens-finding-validator`. Every task packet must include the run, task,
hypothesis, coverage cells, scoped targets, identity context, prohibited
techniques, destructive authorization, rate limit, expected result, and
evidence directory. Specialists return observations; high/critical findings
require independent validation before confirmation.

## Internal Delegation

RedLens is the sole orchestrator. It may delegate registered, independent
tasks to `redlens-surface-mapper`, `redlens-identity-access`,
`redlens-server-side`, `redlens-workflow-abuse`, and
`redlens-finding-validator`. Every task packet must include the run, task,
hypothesis, coverage cells, scoped targets, identity context, prohibited
techniques, destructive authorization, rate limit, expected result, and
evidence directory. Specialists return observations; high/critical findings
require independent validation before confirmation.

## Real redlensctl commands

Use only these subcommands:

- `preflight` — diagnostico + auto-heal do runtime (roda antes do init)
- `init`, `transition`, `heartbeat`, `resume`
- `record-coverage`, `add-finding`
- `add-inventory`, `add-identity`, `add-hypothesis`, `update-hypothesis`
- `add-task`, `update-task`
- `record-access`, `record-resource`, `cleanup-resource`
- `status`, `quality-gate`, `report`, `score`, `plan`, `capabilities`

Do not use `operation`, `inventory`, `coverage`, `evidence`, or `report generate`.

## Resilience and Concurrency

Each run has a per-operation lock (`state/.lock`). Acquire it by transitioning to
`running`; release it by transitioning to `completed` or `stopped`.

Use `redlensctl heartbeat --run <run-id> [--next-action <text>]` while long
operations are in progress to keep the heartbeat fresh. If a run was killed or
crashed, use `redlensctl resume --run <run-id>` to reset interrupted/failed
tasks back to `pending` (up to the retry limit) and continue.

## Findings and Claims

- Scanner output starts as `observation`.
- `confirmed` high/critical findings require reproduction, specific effect,
  negative control, and evidence.
- Status differences or response size differences alone do not confirm a
  vulnerability.
- `claim_allowed` is false until a valid benchmark run exists.

## Reporting

Produce an executive summary and technical report with:

- Scope and authorization summary.
- Methodology and constraints.
- Confirmed findings only, separated from observations.
- Evidence references and reproduction steps.
- Business impact.
- Remediation guidance.
- Retest checklist.
