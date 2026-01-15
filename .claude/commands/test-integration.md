---
description: Run pytest integration tests
allowed-tools: Bash(uv run pytest tests/integration/), "WebFetch(domain:localhost)", "WebFetch(domain:localhost:14000)", "WebFetch(domain:localhost:15000)", "WebFetch(domain:localhost:8055)"
---

Run the integration test suite: `uv run pytest tests/integration/`

If tests fail, or there are warnings, analyze the output and suggest fixes.