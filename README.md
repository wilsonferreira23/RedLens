# RedLens

![RedLens cover](assets/redlens-readme-cover.png)

**Attack your own AI-built app before the internet does.**

RedLens is an authorized, evidence-driven black-box assessment runtime for
Codex and OpenCode. It combines a scoped control plane, a reproducible Kali
container, CloakBrowser and structured reports without mixing operational data
into the source checkout.

## Safety

Use RedLens only on systems you own or are explicitly authorized to assess.
Authorization, target scope, environment, rate limits and prohibited
techniques are binding. High-risk actions require a separate approval.

## Bootstrap

Requirements: Python 3.12+ and Docker Desktop or Docker Engine.

```sh
git clone https://github.com/wilsonferreira23/RedLens.git
cd RedLens
./runtime/bootstrap.sh
```

To build and start the Kali runtime during bootstrap:

```sh
REDLENS_BUILD_RUNTIME=1 ./runtime/bootstrap.sh
```

Keep operational state outside the checkout:

```sh
REDLENS_HOME="$PWD" \
REDLENS_DATA_DIR="/path/to/redlens-data" \
./runtime/bootstrap.sh
```

After installation, run `redlens doctor`, `redlens health` and
`redlens runtime status`.

## Runtime

The persistent `kali-pentest` container supplies the 15-tool Kali set and the
RedLens wrappers. CloakBrowser is the primary browser backend; Playwright is a
fallback only when the primary backend fails. `redlens-health` validates the
container, browser navigation, tools and configured data volume.

For a safe migration of a manually created container to Compose:

```sh
redlens runtime preflight
redlens runtime adopt --image redlens-kali:repro
redlens runtime rollback
```

`preflight` is read-only. `adopt` preserves the prior container with a
versioned name, validates the health check and rolls back if validation fails.

## Use

```text
/pentest https://authorized-target.example
```

The agent asks for authorization and scope before any request, then records
inventory, hypotheses, evidence, coverage and findings in the configured data
directory. Use `quick`, `standard` or `deep` according to the approved scope.

## Layout

- `engine/`: authorization, scope, coverage and quality gates.
- `adapters/`: controlled assessment integrations.
- `runtime/`: Kali image, Compose runtime and mounted workers.
- `opencode/`: OpenCode agent, command and skill adapter.
- `skills/`: portable cross-agent skill package.
- `tests/`: local verification without real targets.

Read [DATA_BOUNDARY.md](DATA_BOUNDARY.md) before sharing a checkout. It
defines the separation between versioned source and private operational data.

## Validation

```sh
python -m unittest discover -s tests -p 'test_*.py'
docker compose -f runtime/compose.yaml config --quiet
redlens-health
```

## License

MIT. See [LICENSE](LICENSE).
