# Execution Environments

Environment documents describe how Kali should be prepared and checked before tool execution.

## Documents

- `server-mode.md` — full Kali VM/server mode, recommended for maximum capability.
- `docker-mode.md` — Docker mode, useful for persistent CLI automation when no Kali server is available.
- `docker-mode-persistent-container.md` — persistent container creation, tool installation, metapackages, wordlists, and custom Dockerfile examples.
- `docker-mode-networking.md` — Docker networking, raw sockets, Docker Desktop limitations, and route troubleshooting.
- `state-files.md` — state directory naming, summary file formats, and raw output conventions.

## Capability Comparison

| Capability | Server Mode | Docker Mode |
|-----------|-------------|-------------|
| Raw sockets | Yes | Limited (needs `--privileged` or `NET_RAW`) |
| GPU cracking | Yes | Requires GPU passthrough setup |
| Wireless adapters | Yes | Not supported in Docker Desktop |
| System services | Yes (systemd) | Manual process management |
| Same-LAN visibility | Yes | Requires `--network host` |
| Database backends | Yes (PostgreSQL, etc.) | Must install and start manually |
| Portability | Tied to host/VM | Highly portable across hosts |
| Isolation | VM-level | Container-level |

## Selection Rule

Prefer full Kali server mode when the task needs raw sockets, same-LAN visibility, wireless hardware, GPU cracking, system services, databases, or service-backed tools. Use Docker only when the task fits persistent CLI automation and the network path is verified.
