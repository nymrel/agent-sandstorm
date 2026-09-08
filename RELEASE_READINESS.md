# Release readiness

Status: **hold — not production grade, not approved for distribution or marketing**

This checklist is the release gate for both the npm and PyPI packages. A checked implementation item is not equivalent to a production approval; all required evidence must be present on the release commit.

## Completed in the current hardening candidate

- [x] Clean Node.js checkout has pinned TypeScript and Node type dependencies plus a lockfile.
- [x] The supported runtime floor is explicit and tested across Node.js 22/24/26 and Python 3.11-3.14, with Node 24 and Python 3.13 pinned for local maintenance.
- [x] TypeScript build fails closed and no longer resolves a compiler from a sibling studio repository.
- [x] Generated npm output includes the runtime `dist/types.js` module and declarations.
- [x] npm package contents are allowlisted and verified without publishing.
- [x] Python source tests run without an ambient `PYTHONPATH`.
- [x] Python wheel contents exclude the repository test suite and are verified without publishing.
- [x] Python builds use an exact Hatchling backend and deterministic wheel/sdist content allowlists instead of a second legacy setup path.
- [x] A nonzero child command fails the enclosing Node.js and Python run by default and requests rollback.
- [x] Rollback refuses symlinked or Windows-junction restore paths and corrupted content-addressed objects instead of writing them.
- [x] Child commands avoid a platform shell by default; shell execution requires explicit caller opt-in.
- [x] Plain HTTP header secrets are blocked in both implementations.
- [x] Allowed domains do not imply arbitrary destination ports; both implementations default to ports 80 and 443 and reject malformed or unapproved ports before dialing upstream.
- [x] Exact domain entries no longer imply arbitrary subdomain access, and wildcard labels have explicit one-label semantics.
- [x] Invalid budget, token, and custom-pricing inputs fail closed instead of reducing or corrupting counters.
- [x] Per-run limiter state resets deterministically, configuration is validated, and disabling loop-pattern checks retains the step ceiling.
- [x] Recognized credentials are redacted from command audit records and default failed-command error objects.
- [x] Omitted allowlists are default-deny, and the Node.js CLI preserves child argument boundaries after `--`.
- [x] Nested audit payloads and derived timestamps are integrity-checked, and report generators escape untrusted HTML content.
- [x] Persisted audit logs continue one chain across runs and reject corrupted history before appending.
- [x] The Python plain HTTP proxy forwards allowed requests instead of returning a synthetic success response.
- [x] Registry publication requires a manual workflow dispatch, an exact existing semantic-version tag checkout, matching Node/Python versions, and an explicit `publish` confirmation.
- [x] Every third-party GitHub Action is pinned to a reviewed immutable commit, credentials are not persisted by checkout, and jobs use least-privilege permissions.
- [x] The default-branch workflow identity delegates pull requests, main pushes, and manual release attempts to the same reusable CI graph, avoiding an unregistered-workflow bootstrap gap.
- [x] Release jobs build one accepted npm archive plus Python wheel/sdist artifacts, record checksums, attest the exact bytes, and use OIDC trusted-publishing boundaries.
- [x] Public documentation states the actual pre-release boundary and removes unsupported benchmark and security guarantees.
- [x] The npm package checker and rollback redirect canaries execute on Windows without relying on ambient shell or symlink privileges.

## Required before a production release

- [ ] Replace in-process callbacks with an enforceable operating-system isolation boundary, or narrow the product contract so it never claims containment.
- [ ] Make outbound policy non-bypassable for the supported execution mode, with DNS/IP validation and documented IPv6 behavior.
- [ ] Decide whether HTTPS inspection is in scope; either implement a reviewed design or explicitly keep secret scanning out of encrypted tunnels.
- [ ] Design and test crash-consistent rollback, including interruption during restore and recovery of partially applied operations.
- [ ] Define and test symlink, hard-link, permission, race, large-file, ignored-path, and cross-filesystem behavior on Linux, macOS, and Windows.
- [ ] Replace static model pricing and voluntary usage reports with versioned price inputs and provider-side budget guidance; never claim pre-charge enforcement without evidence.
- [ ] Add bounded request-body handling, connection limits, timeouts, and proxy abuse tests.
- [ ] Define audit-log durability, locking, retention, rotation, and external-authenticity behavior.
- [ ] Generate and review release SBOM evidence in addition to the checked-in provenance attestation.
- [ ] Resolve or explicitly accept every high-severity static-analysis finding.
- [ ] Record green pull-request CI across the complete Node.js and Python matrices.
- [ ] With explicit repository-settings approval, replace the overclaiming GitHub description and configure required CI checks/branch protection.
- [ ] Complete an independent security review and attach the commit-scoped report.
- [ ] Verify npm scope ownership, PyPI trusted-publisher configuration, protected release environments, and package-name availability without uploading a release.
- [ ] Produce signed release notes, a support policy, and a rollback/yank procedure.
- [ ] Obtain explicit release approval before creating a tag, publishing either package, creating a GitHub release, or beginning marketing.

## Evidence required on the release commit

- CI run URLs for Node.js, Python, package-contract, and security jobs
- npm dry-run manifest and Python wheel/sdist inspection results
- independent review report and resolved findings
- threat-model version and compatibility matrix
- release approval record and exact tag/version
- post-publication install smoke tests from clean environments
