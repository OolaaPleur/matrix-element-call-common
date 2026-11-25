# Matrix Element Call Common

Shared Python utilities for the Matrix Element Call bot ecosystem.

## What's in here

### `matrix_bot_common.cross_signing`

Matrix cross-signing bootstrap logic shared between the music bot, the scrobbler and other bots. Handles:

- Generating Ed25519 master / self-signing / user-signing keypairs
- Uploading them via `/_matrix/client/v3/keys/device_signing/upload`
- Signing the current device key via `/_matrix/client/v3/keys/signatures/upload`
- UIA (User-Interactive Auth) pending-approval flow for `org.matrix.cross_signing_reset`
- Persisting private keys to `data/cross_signing_keys.json` (mode 600, atomic write)
- Never replacing existing keys on the server unless `CROSS_SIGNING_ALLOW_RESET=1` is set (a missing or stale local file only logs a pointer to `scripts/restore_cross_signing_keys.py`)

**Entry point**: `ensure_cross_signing(homeserver, token, user_id, device_id, data_dir)`

## Install

Clone alongside the bot repos (they reference it via `../matrix-element-call-common`):

```bash
git clone https://github.com/OolaaPleur/matrix-element-call-common
# then from any bot directory:
pip install -r requirements.txt
```

Or install directly:

```bash
pip install ../matrix-element-call-common
# or from GitHub:
pip install git+https://github.com/OolaaPleur/matrix-element-call-common
```

## Used by

- [matrix-element-call-musicbot](https://github.com/OolaaPleur/matrix-element-call-musicbot)
- [matrix-element-call-scrobbler](https://github.com/OolaaPleur/matrix-element-call-scrobbler)
- other bots of the author
