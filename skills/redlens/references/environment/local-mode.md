# Local Mode

Local mode means the agent runs directly on a Kali Linux system. Tools are invoked via bash without SSH or Docker wrappers.

## When to Use

Use local mode when:

- the AI agent's host machine is Kali Linux (bare-metal, VM, or WSL),
- tools are already installed or can be installed with `apt-get`,
- no network hop is needed to reach the target.

## Readiness Checks

```bash
whoami && id
uname -a
ip addr
ip route
df -h
apt-get update -qq && echo "apt OK"
ping -c 2 kali.org && echo "network OK"
ls /usr/share/wordlists /usr/share/seclists 2>/dev/null
```

## Operational Notes

- Run tools directly — no `ssh` or `docker exec` wrapper needed.
- State files and raw tool output both live on the local filesystem.
- If the agent user is not root, use `sudo` for privileged operations (package installs, raw sockets, service management).
- Long-running tasks still benefit from output redirection: `nohup {cmd} > /tmp/{task}.log 2>&1 &`.
