# Peirates

- **Category**: Cloud-Native / Kubernetes Exploitation
- **Risk Level**: 🔴 Critical

---

## Description

peirates is a Kubernetes penetration testing tool designed to run from within a compromised container. It performs privilege escalation, lateral movement, and credential harvesting within Kubernetes clusters. Capabilities include stealing service account tokens, executing commands in other pods, mounting secrets, creating privileged pods, accessing cloud provider metadata services, and pivoting between namespaces. Written in Go with an interactive menu-driven interface.

## Installation

```bash
sudo apt install peirates
```

Alternative (from GitHub releases):

```bash
wget https://github.com/inguardians/peirates/releases/latest/download/peirates-linux-amd64.tar.xz
tar xf peirates-linux-amd64.tar.xz
chmod +x peirates
sudo mv peirates /usr/local/bin/
```

## Parameter Reference

### Interactive Menu Options

| Parameter | Description |
|-----------|-------------|
| `[sa-menu]` | Switch between discovered service account tokens |
| `[ns-menu]` | Switch between Kubernetes namespaces |
| `[list]` | List available service account tokens |
| `[exec]` | Execute a command in a running pod |
| `[get-secrets]` | Retrieve secrets from the current namespace |
| `[get-pods]` | List pods in the current namespace |
| `[create-pod]` | Create a new pod (can request privileged access) |
| `[mount-secrets]` | Mount secrets into a pod |
| `[cloud-metadata]` | Access cloud provider metadata endpoint (AWS/GCP/Azure) |
| `[env]` | Dump environment variables (may contain credentials) |
| `[auth-check]` | Check current permissions against the Kubernetes API |
| `[token-hunter]` | Search for service account tokens on the filesystem |
| `[curl]` | Make HTTP requests from within the cluster |

### Command-Line Flags

| Parameter | Description |
|-----------|-------------|
| `-k` | Ignore TLS checking on API server requests |
| `-m <module>` | Run a specific module from the menu (items marked with `*` support this) |
| `-t <token>` | JWT token for authentication |
| `-u <url>` | API server URL (default: `https://10.96.0.1:6443`) |
| `-v` | Verbose mode — display debug messages |

## Common Commands

### Scenario 1: Launch and initial reconnaissance

```bash
# Start peirates (interactive menu)
peirates

# Start with a specific API server URL
peirates -u https://10.96.0.1:6443

# Start with a JWT token
peirates -t <jwt-token>

# Start ignoring TLS verification
peirates -k
```

### Scenario 2: Service account token operations

```bash
# Inside peirates interactive menu:

# List discovered service account tokens
[list]

# Hunt for service account tokens on the filesystem
[token-hunter]

# Switch to a different service account token
[sa-menu]
```

### Scenario 3: Namespace enumeration and secrets

```bash
# Inside peirates interactive menu:

# List pods in current namespace
[get-pods]

# Retrieve secrets from the current namespace
[get-secrets]

# Switch to a different namespace
[ns-menu]
```

### Scenario 4: Lateral movement

```bash
# Inside peirates interactive menu:

# Execute a command in another pod
[exec]

# Create a privileged pod for node-level access
[create-pod]

# Access cloud provider metadata (AWS IMDSv1/GCP/Azure)
[cloud-metadata]
```

### Scenario 5: Credential harvesting

```bash
# Inside peirates interactive menu:

# Dump environment variables from the current pod
[env]

# Mount and read secrets
[mount-secrets]

# Check what the current token is authorized to do
[auth-check]
```

## Notes & Tips

1. peirates is designed to run from inside a compromised container — transfer the binary into the target pod or build a container image that includes it.
2. The `[token-hunter]` feature searches common filesystem paths for service account tokens (e.g., `/var/run/secrets/kubernetes.io/serviceaccount/token`), which can reveal over-permissioned service accounts.
3. The `[cloud-metadata]` option targets cloud provider metadata endpoints (169.254.169.254) to harvest IAM credentials — effective on EKS, GKE, and AKS clusters without metadata protection.
4. Creating privileged pods (`[create-pod]`) enables container escape to the underlying node — this is the highest-impact action and should be clearly scoped in the engagement authorization.
5. All actions use the currently selected service account token — use `[auth-check]` to understand available permissions before attempting privileged operations.

---

## Official References

- [peirates (GitHub)](https://github.com/inguardians/peirates)
- [peirates — Kali Tools](https://www.kali.org/tools/peirates/)
