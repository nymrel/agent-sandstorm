# Changelog

## Unreleased

### Fixed

- Made clean Node.js builds self-contained with pinned compiler and Node type dependencies.
- Restored the missing compiled `dist/types.js` runtime module.
- Made nonzero child commands fail the enclosing Node.js and Python run by default.
- Refused rollback through symlinked path components and verified stored objects before restoration.
- Prevented caller environment overrides from replacing the Node.js proxy variables.
- Treated signal-terminated Node.js commands as failures.
- Blocked recognized secrets in inspectable plain HTTP headers.
- Made non-global custom Node.js secret patterns scan and redact every match without looping.
- Replaced the Python proxy's synthetic success response with forwarding for allowed plain HTTP requests.
- Enforced the Python proxy policy against the absolute request target rather than a conflicting `Host` header.
- Made exact domain entries exact, escaped pattern input, normalized ports/trailing dots, and limited each wildcard to one explicit DNS label.
- Rejected negative, non-finite, and fractional budget/token inputs plus invalid custom pricing.
- Redacted recognized credentials from command audit records and default failed-command errors.
- Made omitted outbound allowlists default-deny and preserved argv boundaries in the Node.js CLI.
- Honored loop-detection opt-outs while retaining step ceilings, validated limiter configuration, and reset limits for each run.
- Covered nested payloads and derived timestamps in audit-chain verification, and escaped untrusted HTML report content.
- Resumed intact persisted audit chains across process runs, rejected corrupted history, and surfaced persistence failures.
- Excluded tests from the Python wheel and added package-content checks for both ecosystems.

### Changed

- Raised the maintained platform floor to Node.js 22/24/26, npm 11, TypeScript 7, and Python 3.11-3.14.
- Replaced the legacy setuptools manifest path with a pinned Hatchling wheel/sdist contract.
- Pinned every GitHub Action to an immutable revision and added fixed Linux, macOS, and Windows acceptance jobs.
- Made publication consume checksummed, attested package artifacts from one exact integrated tag through explicit OIDC trusted-publishing gates.
- Split continuous integration from a manually confirmed publication workflow.
- Stopped tracking generated Node.js output; builds and package checks now create `dist/` deterministically.
- Reframed the project as a pre-release guardrail library and documented its actual security boundary.
