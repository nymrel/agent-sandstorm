# Security Policy

`agent-sandstorm` is engineered from the ground up for high-assurance Zero-Trust execution environments.

## Threat Model & Security Guarantees

Sandstorm defends host developer environments and sensitive production projects against autonomous AI agent misbehavior and supply chain attacks:

| Threat Vector | Mitigation Mechanism | Guarantee |
| :--- | :--- | :--- |
| **Workspace Destruction / Data Loss** | Copy-on-Write (CoW) Merkle tree snapshotting | Instant 1-click atomic rollback to pristine state. Zero permanent data loss. |
| **Secret Exfiltration** | Deep payload inspection & Multi-cloud secret scanner | Blocks outbound requests with OpenAI, Anthropic, AWS, GitHub, GCP, PEM private keys, JWTs, Stripe keys. Returns HTTP 403. |
| **Rogue Outbound Connections** | Zero-Trust Domain Allowlist & Proxy Interception | Denies all unapproved domain connections by default via local forward proxy. |
| **Runaway Financial Drain** | Real-time token budget tracker & USD spend ceiling | Hard-stops agent execution before budget is breached. |
| **Infinite Agent Execution Loops** | Sliding-window N-Gram cycle detector & action frequency brake | Halts repetitive tool loops (period 1 to 5) and enforces step limits. |
| **Tampered Execution Records** | Cryptographic SHA-256 Hash Chained Audit Log | Mathematically verifiable, immutable event journal. Any log modification is instantly flagged. |

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | :white_check_mark: Active security maintenance |

## Reporting a Vulnerability

If you discover a potential security vulnerability in `agent-sandstorm`, please report it immediately:

1. **Email**: `contact@jalenbuilds.com` with the subject line `[SECURITY] agent-sandstorm vulnerability`.
2. Please include:
   - Description of the vulnerability and attack vector
   - Minimal reproducible proof of concept (PoC)
   - Impact assessment
3. We will acknowledge receipt within 24 hours and provide regular status updates until a patch is released.

Please do not open public GitHub issues for undisclosed security vulnerabilities.
