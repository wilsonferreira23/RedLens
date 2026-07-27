# Cloud-Native Security

Tools for authorized cloud, Kubernetes, container image, container registry, and Docker host security assessment. Use this category when the scope includes cloud accounts, Kubernetes clusters, deployment manifests, container images, registries, or Docker hosts.

---

## Golden Path

| Scenario | Primary Tool Chain | When Not to Use |
|----------|-------------------|-----------------|
| Multi-cloud posture review | `scoutsuite` | Use provider-native tools when only one service is in scope |
| AWS compliance and security audit | `prowler aws` | Use ScoutSuite for broader multi-cloud inventory |
| Kubernetes compliance | `kube-bench` | Requires node or cluster access |
| Kubernetes posture/exposure | `kubescape` | Use `trivy config` for IaC-only quick checks |
| Docker host baseline | `docker-bench-security` | Requires Docker host access |
| Docker registry/API exposure | `skopeo` + `curl` | Use Docker CLI for local image inspection |
| AWS exploitation | `pacu` | Use `prowler` or `scoutsuite` for configuration audits |

---

## Cloud Configuration Audit

**[ScoutSuite](tools/scoutsuite.md)** — Multi-cloud security auditing
Enumerates cloud configuration across providers and produces local reports. Use when broad account posture and cross-service inventory are in scope.

**[Prowler](tools/prowler.md)** — Cloud compliance and security assessment
Strong AWS coverage with additional provider support. Use for CIS/compliance checks, IAM, S3, logging, network exposure, and encryption findings.

**[azurehound](tools/azurehound.md)** — Azure AD/ARM data collection for BloodHound
Collects Azure Active Directory and Azure Resource Manager data for import into BloodHound, enabling attack path mapping across Azure tenants. Identifies privilege escalation paths, role assignments, and resource access chains in Azure environments.

---

## Cloud Exploitation

**[pacu](tools/pacu.md)** — AWS exploitation framework
An open-source AWS exploitation framework with modules for IAM enumeration, privilege escalation, data exfiltration, persistence, and lateral movement across AWS services. Complements `prowler`/`scoutsuite` — the latter for configuration audits, `pacu` for active exploitation testing.

---

## Kubernetes Security

**[kube-bench](tools/kube-bench.md)** — CIS Kubernetes Benchmark checks
Audits nodes and cluster configuration against the CIS Kubernetes Benchmark.

**[kubescape](tools/kubescape.md)** — Kubernetes posture and manifest scanning
Scans clusters, manifests, and Helm charts against security frameworks such as NSA, MITRE ATT&CK, and CIS.

**[peirates](tools/peirates.md)** — Kubernetes penetration testing
An offensive tool for Kubernetes environments covering privilege escalation, credential harvesting, lateral movement, and container escape techniques. Use after gaining initial access to a pod or cluster to enumerate attack paths.

---

## Docker and Registry Security

**[docker-bench-security](tools/docker-bench-security.md)** — Docker host CIS-style audit
Checks Docker daemon, containers, images, networking, logging, and Docker socket exposure.

---

## Related Categories

- For quick container image, filesystem, repository, IaC, SBOM, and secret scanning, read `../vulnerability/tools/trivy.md`.

---

## Assessment Workflow by Provider

Match the target environment to the right tool chain:

| Target | Tool Chain |
|--------|------------|
| AWS account | `prowler aws` (CIS, IAM, S3, logging, encryption) + `pacu` (exploitation: IAM escalation, data exfil) |
| Azure subscription | `prowler azure` (CIS, RBAC, storage, networking) |
| GCP project | `prowler gcp` (CIS, IAM, storage, compute) |
| Multi-cloud | `scoutsuite` (cross-provider inventory + posture) |
| Kubernetes cluster | `kube-bench` (CIS node audit) + `kubescape` (posture/manifest frameworks) |
| Containers / images | `trivy` (image + filesystem CVEs) + `docker-bench-security` (host baseline) |

---

## Playbook

For the full scenario workflow, priority checks, and risk gates, see `../playbooks/cloud-native-assessment.md`.

## Decision Tree

Select the approach when the Golden Path doesn't fit:

| Condition | Action |
|-----------|--------|
| Azure tenant, need attack path mapping | `azurehound` to collect data → BloodHound for path visualization |
| Kubernetes pod access gained (post-exploitation) | `peirates` for privilege escalation, credential harvesting, and container escape |
| Docker socket exposed (2375/2376) | `docker -H tcp://<host>:2375 info` → container escape via privileged mount |
| Registry API exposed without auth | `skopeo list-tags` → pull images → `trivy` for secrets/CVEs |

---

## Official References

- [ScoutSuite GitHub](https://github.com/nccgroup/ScoutSuite)
- [Prowler Documentation](https://docs.prowler.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Docker Documentation](https://docs.docker.com/)
