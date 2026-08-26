# Security policy

`agent-sandstorm` is experimental and has no supported public release. The `main` branch receives best-effort maintenance while the release-readiness gate remains open.

## Intended boundary

Sandstorm adds recoverability and observability around trusted development commands. It is intended for disposable or backed-up workspaces where the caller understands and accepts the exclusions below.

It is not a replacement for a virtual machine, container, restricted operating-system account, mandatory access control, network namespace, egress firewall, provider-side budget, or tested backup and restore system.

| Control | What it currently covers | What it does not cover |
| --- | --- | --- |
| Workspace snapshot | Regular files selected by the scanner | Excluded directories, symlinks, hard links, file locks, external stores, or process state |
| Rollback | Sequential restoration of captured regular files | Crash-atomic restoration or recovery from host/process termination during rollback |
| Domain filter | Requests from proxy-aware child processes | Direct sockets, software that ignores proxy variables, DNS rebinding, or host-level enforcement |
| Secret scan | Inspectable plain HTTP URLs, headers, and bodies | Encrypted HTTPS payloads inside `CONNECT` tunnels or traffic that bypasses the proxy |
| Execution limits | Steps and usage explicitly recorded through the context | Unreported calls, provider-side billing state, or arbitrary work performed between checkpoints |
| Audit chain | Detection of edits to a retained sequence of events | Authenticity against an external trust root, deletion of the whole log, or immutable storage |

Recognized credential patterns are redacted from Sandstorm-generated command and failure audit fields and from default failed-command error objects. Successful command output, caller-defined audit payloads, and results returned with the explicit nonzero opt-out remain caller-controlled and must be handled as potentially sensitive.

A new logger resumes an intact existing JSONL chain and refuses to append to corrupted history. Concurrent writers and external log authenticity are not supported.

## Known release blockers

The authoritative list is [RELEASE_READINESS.md](./RELEASE_READINESS.md). Until those blockers are closed:

- do not run unknown or hostile code on a valuable host;
- do not describe Sandstorm as zero-risk, tamper-proof, atomic, or non-bypassable;
- do not rely on it to protect credentials or enforce financial limits;
- do not enable shell execution for command text influenced by an untrusted party;
- do not publish the reserved npm or PyPI package names.

## Reporting a vulnerability

Email `contact@nymrel.com` with the subject `[SECURITY] agent-sandstorm vulnerability`. Include the affected commit, a minimal reproduction, expected and observed behavior, and an impact assessment. Do not include live secrets or production data, and do not open a public issue for an undisclosed vulnerability.

Receipt and remediation timelines are not guaranteed while the project remains pre-release.
