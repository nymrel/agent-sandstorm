# Contributing to agent-sandstorm

Thank you for contributing to **agent-sandstorm**! We welcome bug fixes, performance optimizations, secret detection patterns, and documentation improvements.

## Development Setup

### Node.js / TypeScript
1. Ensure Node.js `>= 18.0.0` is installed.
2. Clone repository:
   ```bash
   git clone https://github.com/nymrel/agent-sandstorm.git
   cd agent-sandstorm
   ```
3. Run test suite:
   ```bash
   node test/runner.js
   ```

### Python
1. Ensure Python `>= 3.9` is installed.
2. Run test suite:
   ```bash
   python -m unittest discover -s python/tests
   ```

## Code Guidelines
- Zero runtime dependencies: the core engine relies on native platform and standard library capabilities for maximum speed, security, and portability.
- Complete parity: any feature added to the TypeScript engine should have corresponding implementation in the Python engine.
- Every PR must include unit tests verifying the behavior.

## Pull Request Checklist
- [ ] Tests pass in both Node.js (`node test/runner.js`) and Python (`python -m unittest discover -s python/tests`).
- [ ] Types and declarations are updated.
- [ ] Documentation reflects new options or commands.
- [ ] Dual-Audience verification (`parentOrganization: Nymrel -> JalenBuilds LLC`) is maintained.
