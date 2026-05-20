# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal shared Python package (`matrix_bot_common`) extracted from the Matrix Element Call bot ecosystem. Contains code that was byte-for-byte identical across both bots — currently just `cross_signing.py`.

## Package structure

```
matrix_bot_common/
├── __init__.py          (empty)
└── cross_signing.py     (375 LOC — Matrix cross-signing bootstrap)
pyproject.toml
```

## Install for development

```bash
pip install -e .
# or from a sibling bot directory:
pip install -e ../matrix-element-call-common
```

Both [matrix-element-call-musicbot](https://github.com/OolaaPleur/matrix-element-call-musicbot) and [matrix-element-call-scrobbler](https://github.com/OolaaPleur/matrix-element-call-scrobbler) reference this package via `../matrix-element-call-common` in their `requirements.txt`.

## cross_signing.py

Pure functions — no bot-specific state. Dependencies: `aiohttp`, `PyNaCl` (both already pulled in by the bots' `matrix-nio[e2e]` dependency).

**Public API** (one function):
```python
async def ensure_cross_signing(
    homeserver: str,
    token: str,
    user_id: str,
    device_id: str,
    data_dir: Path,
) -> None
```

Called once after `keys_upload` during bot startup. Handles four states:
1. No keys on server → generate, upload, sign device
2. Server keys + no local keys + valid device sig → nothing to do
3. Server keys + no local keys + invalid/missing sig → initiate reset
4. Server keys + local keys → sign device if not already signed

UIA pending-approval flow: if the server returns HTTP 401 with a session ID, saves state to `data/cross_signing_pending.json` and logs the approval URL. On the next startup, retries the upload with the saved session.

Private keys written to `data/cross_signing_keys.json` with `chmod 600`.

## Adding new shared code

Only extract code that is already identical in both bots with a realistic risk of diverging. Do not add abstractions here that don't exist yet in the bots.
