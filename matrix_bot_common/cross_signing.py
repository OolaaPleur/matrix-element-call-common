import base64
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

import aiohttp
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

logger = logging.getLogger(__name__)

_PENDING_FILE = "cross_signing_pending.json"
_KEYS_FILE = "cross_signing_keys.json"
_UIA_TYPE = "org.matrix.cross_signing_reset"
_DEFAULT_APPROVAL_URL = "https://account.matrix.org/account/?action=org.matrix.cross_signing_reset"
# A UIA session doesn't live forever; an older pending file would only block the normal checks.
_PENDING_MAX_AGE = 24 * 3600
# Replacing the account's cross-signing keys un-verifies the bot everywhere, so when the
# server already has keys the bot can't use, it only does that if explicitly allowed.
_ALLOW_RESET_ENV = "CROSS_SIGNING_ALLOW_RESET"
_RESTORE_HINT = (
    "Restore the file with matrix-element-call-common/scripts/restore_cross_signing_keys.py "
    f"(needs the recovery key), or set {_ALLOW_RESET_ENV}=1 to replace the account's keys."
)
_SK_FIELDS = ("master_sk", "self_signing_sk", "user_signing_sk")


def _b64(b: bytes) -> str:
    return base64.b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _sign_obj(sk: SigningKey, obj: dict) -> str:
    return _b64(sk.sign(_canonical_json(obj)).signature)


def _write_private(path: Path, data: dict) -> None:
    """Write JSON readable by the owner only, atomically; the file never exists with wider permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        os.fchmod(f.fileno(), 0o600)
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


@dataclass
class CrossSigningKeys:
    master_sk: bytes
    self_signing_sk: bytes
    user_signing_sk: bytes
    master_pub: str
    self_signing_pub: str
    user_signing_pub: str

    def to_dict(self) -> dict:
        d = asdict(self)
        for f in _SK_FIELDS:
            d[f] = _b64(d[f])
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CrossSigningKeys":
        return cls(**{f: _unb64(d[f]) if f in _SK_FIELDS else d[f] for f in cls.__dataclass_fields__})


def generate_keys(user_id: str) -> tuple[CrossSigningKeys, dict]:
    """Generate three Ed25519 keypairs and return (local_keys, upload_payload)."""
    sks = {usage: SigningKey.generate() for usage in ("master", "self_signing", "user_signing")}
    pubs = {usage: _b64(bytes(sk.verify_key)) for usage, sk in sks.items()}

    payload = {}
    for usage, pub in pubs.items():
        obj = {"user_id": user_id, "usage": [usage], "keys": {f"ed25519:{pub}": pub}}
        if usage != "master":
            obj["signatures"] = {user_id: {f"ed25519:{pubs['master']}": _sign_obj(sks["master"], obj)}}
        payload[f"{usage}_key"] = obj

    local = CrossSigningKeys(
        master_sk=bytes(sks["master"]),
        self_signing_sk=bytes(sks["self_signing"]),
        user_signing_sk=bytes(sks["user_signing"]),
        master_pub=pubs["master"],
        self_signing_pub=pubs["self_signing"],
        user_signing_pub=pubs["user_signing"],
    )
    return local, payload


def load_local_keys(data_dir: Path) -> Optional[CrossSigningKeys]:
    path = data_dir / _KEYS_FILE
    if not path.exists():
        return None
    try:
        return CrossSigningKeys.from_dict(json.loads(path.read_text()))
    except Exception as exc:
        logger.error("Cross-signing: failed to load local keys: %s", exc)
        return None


def save_local_keys(data_dir: Path, keys: CrossSigningKeys) -> None:
    path = data_dir / _KEYS_FILE
    _write_private(path, keys.to_dict())
    logger.info("Cross-signing: private keys saved to %s", path)


def load_pending(data_dir: Path) -> Optional[dict]:
    path = data_dir / _PENDING_FILE
    if not path.exists():
        return None
    try:
        p = json.loads(path.read_text())
    except Exception:
        return None
    if time.time() - p.get("created_at", path.stat().st_mtime) > _PENDING_MAX_AGE:
        expired = path.with_name(path.name + ".expired")
        path.replace(expired)
        logger.warning("Cross-signing: pending approval is older than a day, moved to %s and ignored", expired.name)
        return None
    return p


def save_pending(data_dir: Path, session_id: str, payload: dict, keys: CrossSigningKeys) -> None:
    _write_private(data_dir / _PENDING_FILE, {
        "session_id": session_id,
        "created_at": time.time(),
        "payload": payload,
        **keys.to_dict(),
    })


def clear_pending(data_dir: Path) -> None:
    (data_dir / _PENDING_FILE).unlink(missing_ok=True)


async def _json(r: aiohttp.ClientResponse) -> dict:
    try:
        data = await r.json(content_type=None)
    except Exception:
        data = None
    return data if isinstance(data, dict) else {"raw": (await r.text())[:200]}


async def _query_server(homeserver: str, token: str, user_id: str) -> dict:
    """Return the keys/query response; raise on anything but HTTP 200.

    An error response has no master_keys, which would otherwise read as "no keys on the
    server" and start a key reset.
    """
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{homeserver}/_matrix/client/v3/keys/query",
            json={"device_keys": {user_id: []}},
            headers={"Authorization": f"Bearer {token}"},
        ) as r:
            data = await _json(r)
            if r.status != 200:
                raise RuntimeError(f"keys/query returned HTTP {r.status}: {data}")
            return data


async def _upload_signing_keys(
    homeserver: str, token: str, payload: dict, auth: Optional[dict] = None
) -> tuple[bool, Optional[str], Optional[str]]:
    """Returns (success, session_id, approval_url)."""
    body = dict(payload)
    if auth:
        body["auth"] = auth
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{homeserver}/_matrix/client/v3/keys/device_signing/upload",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        ) as r:
            data = await _json(r)
            if r.status == 200:
                return True, None, None
            if r.status == 401 and data.get("session"):
                url = next(
                    (v["url"] for v in data.get("params", {}).values() if isinstance(v, dict) and "url" in v),
                    None,
                )
                return False, data["session"], url
            logger.error("Cross-signing upload unexpected response %s: %s", r.status, data)
            return False, None, None


def _verify_device_sig(server_data: dict, user_id: str, device_id: str, ss_pub: str) -> bool:
    device = server_data.get("device_keys", {}).get(user_id, {}).get(device_id)
    if not device:
        return False
    sig_b64 = device.get("signatures", {}).get(user_id, {}).get(f"ed25519:{ss_pub}")
    if not sig_b64:
        return False
    to_verify = {k: v for k, v in device.items() if k not in ("signatures", "unsigned")}
    try:
        VerifyKey(_unb64(ss_pub)).verify(_canonical_json(to_verify), _unb64(sig_b64))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


async def _sign_device(
    homeserver: str,
    token: str,
    user_id: str,
    device_id: str,
    ss_sk_bytes: bytes,
    server_data: dict,
) -> bool:
    ss_sk = SigningKey(ss_sk_bytes)
    ss_pub = _b64(bytes(ss_sk.verify_key))

    device = server_data.get("device_keys", {}).get(user_id, {}).get(device_id)
    if not device:
        logger.error("Cross-signing: device %s not found in server keys query", device_id)
        return False

    to_sign = {k: v for k, v in device.items() if k not in ("signatures", "unsigned")}
    existing = device.get("signatures", {}).get(user_id, {})
    signed_device = {
        **device,
        "signatures": {user_id: {**existing, f"ed25519:{ss_pub}": _sign_obj(ss_sk, to_sign)}},
    }

    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{homeserver}/_matrix/client/v3/keys/signatures/upload",
            json={user_id: {device_id: signed_device}},
            headers={"Authorization": f"Bearer {token}"},
        ) as r:
            data = await _json(r)
            if r.status == 200 and not data.get("failures"):
                return True
            logger.error("Cross-signing: signature upload failed %s: %s", r.status, data)
            return False


def _log_approval_needed(user_id: str, url: Optional[str]) -> None:
    logger.warning(
        "Cross-signing: the server needs the account owner to approve replacing the keys.\n"
        "  → Visit: %s\n"
        "  Log in as the BOT account: %s\n"
        "  Then restart the bot to complete setup.",
        url or _DEFAULT_APPROVAL_URL, user_id,
    )


async def _finish(homeserver: str, token: str, user_id: str, device_id: str,
                  data_dir: Path, keys: CrossSigningKeys) -> None:
    """The server accepted the keys: keep them and sign this device."""
    save_local_keys(data_dir, keys)
    clear_pending(data_dir)
    server_data = await _query_server(homeserver, token, user_id)
    if await _sign_device(homeserver, token, user_id, device_id, keys.self_signing_sk, server_data):
        logger.info("Cross-signing: fully set up, device %s signed", device_id)


async def _upload_new_keys(homeserver: str, token: str, user_id: str, device_id: str, data_dir: Path) -> None:
    keys, payload = generate_keys(user_id)
    ok, session_id, url = await _upload_signing_keys(homeserver, token, payload)
    if ok:
        await _finish(homeserver, token, user_id, device_id, data_dir, keys)
    elif session_id:
        save_pending(data_dir, session_id, payload, keys)
        _log_approval_needed(user_id, url)
    else:
        logger.error("Cross-signing: key upload failed, skipping")


async def ensure_cross_signing(
    homeserver: str,
    token: str,
    user_id: str,
    device_id: str,
    data_dir: Path,
) -> None:
    """
    Called once after keys_upload during bot startup.
    Ensures cross-signing keys exist and the current device is validly signed.
    Never raises: a failure is logged and the bot keeps running with the device unsigned.
    """
    try:
        await _ensure(homeserver, token, user_id, device_id, data_dir)
    except Exception as exc:
        logger.warning("Cross-signing: skipped after an error: %s", exc)


async def _ensure(homeserver: str, token: str, user_id: str, device_id: str, data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)

    # --- A key replacement from a previous startup is waiting for approval ---
    pending = load_pending(data_dir)
    if pending:
        logger.info("Cross-signing: pending approval found — attempting UIA completion")
        auth = {"type": _UIA_TYPE, "session": pending["session_id"]}
        ok, _, url = await _upload_signing_keys(homeserver, token, pending["payload"], auth=auth)
        if ok:
            logger.info("Cross-signing: approval accepted, keys uploaded")
            await _finish(homeserver, token, user_id, device_id, data_dir, CrossSigningKeys.from_dict(pending))
        else:
            _log_approval_needed(user_id, url)
        return

    server_data = await _query_server(homeserver, token, user_id)
    server_pub = {
        name: next(iter(server_data.get(f"{name}_keys", {}).get(user_id, {}).get("keys", {}).values()), None)
        for name in ("master", "self_signing", "user_signing")
    }

    # --- No keys on the server: a fresh account, set it up ---
    if not all(server_pub.values()):
        logger.info("Cross-signing: no keys on server, generating new keypairs and uploading")
        await _upload_new_keys(homeserver, token, user_id, device_id, data_dir)
        return

    ss_pub = server_pub["self_signing"]
    local_keys = load_local_keys(data_dir)
    # The local file can be stale: the account's keys were reset later (e.g. from Element).
    # Signing with it is useless, and the upload would still "succeed" because the payload
    # carries the device's existing valid signature.
    if local_keys is None:
        problem = f"no {_KEYS_FILE}"
    elif local_keys.self_signing_pub != ss_pub:
        problem = (f"{_KEYS_FILE} is stale (self-signing key {local_keys.self_signing_pub[:8]}… locally, "
                   f"{ss_pub[:8]}… on the server)")
    else:
        problem = None

    if _verify_device_sig(server_data, user_id, device_id, ss_pub):
        logger.info("Cross-signing: device %s already validly signed, nothing to do", device_id)
        if problem and local_keys is not None:
            logger.warning("Cross-signing: %s; new devices can't be signed. %s", problem, _RESTORE_HINT)
        return

    if problem is None:
        logger.info("Cross-signing: signing device %s", device_id)
        if await _sign_device(homeserver, token, user_id, device_id, local_keys.self_signing_sk, server_data):
            logger.info("Cross-signing: device %s signed and signature uploaded successfully", device_id)
        else:
            logger.error("Cross-signing: failed to sign device %s", device_id)
        return

    # --- Device unsigned and no usable private keys ---
    if os.environ.get(_ALLOW_RESET_ENV) == "1":
        logger.warning("Cross-signing: device %s NOT signed, %s; %s=1, replacing the account's keys",
                       device_id, problem, _ALLOW_RESET_ENV)
        await _upload_new_keys(homeserver, token, user_id, device_id, data_dir)
        return
    logger.warning("Cross-signing: device %s NOT signed, %s. %s", device_id, problem, _RESTORE_HINT)
