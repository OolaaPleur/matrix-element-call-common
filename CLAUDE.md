# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A minimal shared Python package (`matrix_bot_common`) extracted from the Matrix bot ecosystem — currently just `cross_signing.py`. Used by five bots: musicbot and scrobbler (installed from the sibling checkout, `../matrix-element-call-common` in `requirements.txt` — a plain copy, not editable, so reinstall after changes) and the three Navi bots `navi-assistant`, `navi-anki`, `navi-feeds` (pinned to a commit of this GitHub repo in their `pyproject.toml`/`uv.lock` — bump the pin after changes; they share one account's keys in `~/.local/share/navi-account/`). `navi-anki/scripts/sign_device.py` imports `_query_server`, `_sign_device`, `_verify_device_sig` and `load_local_keys` — keep those names.

## Package structure

```
matrix_bot_common/
├── __init__.py          (empty)
└── cross_signing.py     (Matrix cross-signing bootstrap)
scripts/restore_cross_signing_keys.py  (rewrite a stale keys file from secret storage; needs the recovery key)
pyproject.toml
```

## Install for development

```bash
pip install -e .
# or from a sibling bot directory:
pip install -e ../matrix-element-call-common
```

[matrix-element-call-musicbot](https://github.com/OolaaPleur/matrix-element-call-musicbot) and [matrix-element-call-scrobbler](https://github.com/OolaaPleur/matrix-element-call-scrobbler) reference this package via `../matrix-element-call-common` in their `requirements.txt`; the Navi bots via `git+https://github.com/OolaaPleur/matrix-element-call-common@<commit>`.

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

Called once after `keys_upload` during bot startup. **Never raises** (errors are logged as a warning; the Navi bots call it without a try). Order of checks:
1. A pending approval (`data/cross_signing_pending.json`, from an earlier UIA 401) → retry the upload with the saved session; on success save the keys and sign the device. Pending files older than a day or unreadable (no `session_id`/payload/keys) are moved to `.expired` and ignored. A non-401 answer to the retry (5xx, 429) keeps the file and retries next start instead of asking for approval again.
2. `keys/query` must return HTTP 200, otherwise skip. (Before 2026-11-25 an error response — 429, 401 — read as "no keys on the server" and started a key reset.)
3. No keys at all on the server (fresh account) → generate, upload (UIA → pending + approval URL from the server's response), sign the device.
4. Device already validly signed by the server's self-signing key → nothing to do; if the local keys file is missing (info) or stale (warning), say so — a new device couldn't be signed.
5. Local keys match the server → sign the device.
6. Otherwise (local file missing or stale, or the server has only part of the key set) → **warn and point to `scripts/restore_cross_signing_keys.py`; never replace the account's keys** unless the bot runs with `CROSS_SIGNING_ALLOW_RESET=1` (replacing them un-verifies the bot everywhere — the Navi account's green shield included).

Private keys are written atomically with mode 600 from the start and fsync'ed before the rename (`_write_private`), to `data/cross_signing_keys.json`; the JSON format is unchanged and shared with `navi-anki/scripts/setup_secret_storage.py` and musicbot's `scripts/show_cross_signing_fingerprint.py`.

## Adding new shared code

Only extract code that is already identical in the bots with a realistic risk of diverging. Do not add abstractions here that don't exist yet in the bots.
