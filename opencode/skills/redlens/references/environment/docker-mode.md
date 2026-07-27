# Docker Mode

Use Docker mode when no Kali SSH server is available and the task can run with CLI tools inside a persistent Kali container.

Docker is an execution environment, not just an installation method. Keep the container persistent so installed tools and generated artifacts remain available across sessions.

## Recommended Use

| Scenario | Recommended approach |
|---|---|
| Full Kali SSH server available | Use SSH/server mode |
| No Kali server, Docker available | Use a persistent named container |
| Reproducible local environment | Use a custom Dockerfile |
| Same-LAN, ARP-dependent, wireless, raw-socket-heavy, or service-heavy work | Prefer SSH to a full Kali VM/server |

## Agent Workflow

1. Check whether the persistent container exists.
2. Start it if it is stopped.
3. Install missing tools into the persistent container, not a temporary container.
4. Run Kali commands with `docker exec`.
5. Copy needed artifacts out with `docker cp`.
6. Stop the container when finished; do not remove it.

## Script Delivery

When sending Python or shell scripts into the container, use `docker cp` instead of heredoc piping — heredocs introduce CRLF line endings (macOS) and shell variable conflicts (e.g., `UID` is readonly in bash).

```bash
cat > /tmp/script.py << 'EOF'
# script content
EOF
docker cp /tmp/script.py kali-pentest:/tmp/script.py
docker exec kali-pentest python3 /tmp/script.py
```

Avoid f-strings with nested quotes in scripts delivered this way — use `%` formatting or pre-computed variables to prevent escaping issues across shell layers.

## Documents

- `docker-mode-persistent-container.md` — persistent container creation, tool installation, metapackages, wordlists, and custom Dockerfile examples.
- `docker-mode-networking.md` — host networking, raw sockets, Docker Desktop limitations, reachability checks, and route troubleshooting.

## Official References

- [Kali Linux Docker Hub](https://hub.docker.com/u/kalilinux)
- [Kali Linux Docker Documentation](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
