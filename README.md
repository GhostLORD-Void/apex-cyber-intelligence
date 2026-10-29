# APEX Cyber Intelligence

A cross-platform, local-first security research workbench. The initial release focuses on **defensive analysis and explicitly authorized lab workflows**: evidence hashing, static file triage, URL/domain parsing without network contact, scope validation, and reproducible JSON reports.

> APEX does not disable model safeguards, attack arbitrary public targets, execute exploit payloads, or perform stealth/persistence. Network-active testing is intentionally out of scope for this starter release.

## Features

- FastAPI service with a small web API
- SHA-256 evidence fingerprints and metadata
- Static text triage for URLs, IP literals, email addresses, and suspicious keywords
- URL parsing without DNS resolution or HTTP requests
- Explicit target-scope registry for documenting authorized lab assets
- JSON report export
- CLI for offline file analysis
- pytest suite and GitHub Actions CI
- Termux-friendly setup (Python only)

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn apex.api:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000/docs.

## CLI

```bash
python -m apex.cli analyze ./sample.txt --out report.json
```

## API

- `GET /health`
- `POST /v1/analyze/text` JSON: `{"text":"..."}`
- `POST /v1/analyze/file` multipart upload (max 10 MiB)
- `POST /v1/scope/validate` JSON: `{"target":"https://lab.example","allowed":["lab.example"]}`

Scope validation is a documentation/control helper, not proof of authorization. You remain responsible for obtaining written permission and respecting engagement boundaries.

## Termux (Android)

```bash
pkg update -y
pkg install python git -y
git clone https://github.com/GhostLORD-Void/apex-cyber-intelligence.git
cd apex-cyber-intelligence
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest -q
uvicorn apex.api:app --host 127.0.0.1 --port 8000
```

Keep the server bound to localhost unless you deliberately configure and secure remote access.

## Configuration

- `APEX_MAX_UPLOAD_BYTES`: upload limit; default 10485760
- `APEX_API_TOKEN`: optional bearer token. If set, API routes (except health) require it.

Example:
```bash
export APEX_API_TOKEN='replace-with-a-long-random-secret'
```

## Project layout

```
apex/          application package
tests/         automated tests
scripts/       Termux helper
.github/       CI workflow
```

## Roadmap

1. Local LLM adapter with explicit tool allowlists and human approval gates
2. Persistent case workspace and evidence provenance
3. Plugin interface for offline scanners and lab-only integrations
4. Benchmark harness for evaluating analysis quality (no autonomous self-modification)

Contributions should include tests and must preserve the authorization and safety boundaries.
