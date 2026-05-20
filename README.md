# Matrix Element Call Common

Shared Python utilities for the Matrix Element Call bot ecosystem.

## What's in here

### `matrix_bot_common.cross_signing`

Matrix cross-signing bootstrap logic shared between the music bot and scrobbler. Handles:

- Generating Ed25519 master / self-signing / user-signing keypairs
- Uploading them via `/_matrix/client/v3/keys/device_signing/upload`
- Signing the current device key via `/_matrix/client/v3/keys/signatures/upload`
- UIA (User-Interactive Auth) pending-approval flow for `org.matrix.cross_signing_reset`
- Persisting private keys to `data/cross_signing_keys.json` (chmod 600)

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
