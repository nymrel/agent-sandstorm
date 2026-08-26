# Contributing to agent-sandstorm

The project is pre-release. Contributions should reduce a documented release blocker, add a regression test, or make the security boundary more precise.

## Development setup

Node.js 18+ and Python 3.9+ are required.

```bash
npm ci
npm run test:node
npm run check:package
python scripts/test_python.py
```

To validate the Python distribution:

```bash
python -m pip install --upgrade build twine
python -m build --outdir python-dist
python -m twine check python-dist/*
python scripts/check_python_package.py python-dist
```

## Pull request contract

- Start from current `main` and keep the change focused on one release blocker.
- Add regression tests for behavior changes in both implementations when parity is claimed.
- Treat a nonzero command, failed build, missing dependency, audit finding, or missing artifact as a failure unless the exception is explicit and documented.
- Do not add production, security, performance, compatibility, or distribution claims without reproducible evidence.
- Do not add real credentials, customer data, network calls, payments, publishing, deployment, or destructive host-level test behavior.
- Update `README.md`, `SECURITY.md`, and `RELEASE_READINESS.md` when the public boundary changes.

No pull request should publish a package, create a release, deploy a service, or change registry/repository settings. Those actions use a separate approval and release process.
