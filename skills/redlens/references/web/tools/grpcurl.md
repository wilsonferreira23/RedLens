# gRPCurl

- **Category**: Web / API gRPC Testing
- **Risk Level**: 🟡 Medium

---

## Description

Command-line gRPC client for listing services, describing methods, and invoking RPC calls. Use it to test reflection exposure, metadata authentication, and gRPC method behavior.

## Installation

```bash
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-plaintext` | Disable TLS |
| `-insecure` | Skip TLS certificate verification |
| `-proto <file>` | Proto file to use for request parsing and formatting (when reflection unavailable) |
| `-protoset <file>` | Compiled protoset file (from `protoc --descriptor_set_out`) |
| `-import-path <dir>` | Path for proto file imports |
| `-H <header>` | Add metadata/header (format: `name: value`) |
| `-d <json>` | Request body as JSON |
| `-format <fmt>` | Format for request data: `json` (default) or `text` |
| `-v` | Verbose output (show headers and trailers) |
| `-vv` | Very verbose (show raw bytes) |
| `list` | List services or methods |
| `describe` | Describe service or method |
| `<host:port> <method>` | Invoke method |

## Common Commands

```bash
# List services via reflection
grpcurl -plaintext <target>:50051 list

# Describe a service
grpcurl -plaintext <target>:50051 describe <service>

# Invoke method with JSON body
grpcurl -plaintext -d '{"id":"123"}' <target>:50051 <service>/<method>

# Authenticated metadata
grpcurl -H "authorization: Bearer <token>" <target>:443 list
```

## Notes & Tips

1. Reflection exposure is an information disclosure finding when it reveals internal methods or messages.
2. If reflection is disabled, provide `.proto` files with `-proto` when available.
3. Avoid invoking state-changing RPCs unless explicitly authorized.

---

## Official References

- [grpcurl GitHub](https://github.com/fullstorydev/grpcurl)
