"""Restore a bot's cross-signing private keys from Matrix secret storage (4S).

For a bot account whose cross-signing keys were set up elsewhere (usually in
Element, with "Set up recovery") or by an earlier install whose
data/cross_signing_keys.json is gone or stale: the bot can't sign its device
until it has the private keys. Asks for the account's recovery key (no echo),
decrypts the three private keys from secret storage, checks that they match
the public keys on the server, keeps an old file as
cross_signing_keys.json.stale-<date> and writes the new one (mode 600).
Prints only public key prefixes. Restart the bot afterwards.

Run it in the bot's directory (the one with data/), with the bot's Python:

    python3 -m matrix_bot_common.restore_keys
    docker compose exec <service> python3 -m matrix_bot_common.restore_keys

The bot directory can also be given as an argument. The homeserver and token
come from the bot's config (CONFIG_FILE, else config.toml, else
config/config.toml), else data/credentials.json, else data/access_token (bots
that log in by password). Bots can also call restore() from their own setup.
"""
import base64
import datetime
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util import Counter
from nacl.signing import SigningKey

from matrix_bot_common import cross_signing as cs

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECRETS = {"master": "m.cross_signing.master", "self_signing": "m.cross_signing.self_signing",
           "user_signing": "m.cross_signing.user_signing"}
# Cloudflare in front of some homeservers (matrix.org) rejects urllib's default User-Agent.
USER_AGENT = "matrix-bot-common restore_keys"


class Abort(Exception):
    """A problem to report to the user; nothing has been changed."""


def decode_recovery_key(text: str) -> bytes:
    s = re.sub(r"\s+", "", text)
    if not s or any(ch not in B58 for ch in s):
        raise Abort("That doesn't look like a recovery key (unexpected characters).")
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) != 35 or raw[:2] != b"\x8b\x01":
        raise Abort("That doesn't look like a recovery key (wrong length or prefix).")
    parity = 0
    for b in raw:
        parity ^= b
    if parity:
        raise Abort("Recovery key parity check failed (typo?).")
    return raw[2:34]


def _derive(key: bytes, name: str):
    okm = HKDF(key, 64, b"\x00" * 32, SHA256, context=name.encode())
    return okm[:32], okm[32:]


def _b64_loose(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _decrypt(key: bytes, name: str, enc: dict) -> bytes:
    aes_key, mac_key = _derive(key, name)
    ct = base64.b64decode(enc["ciphertext"])
    if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), _b64_loose(enc["mac"])):
        raise Abort(f"Secret {name} doesn't decrypt with this key (bad MAC).")
    ctr = Counter.new(128, initial_value=int.from_bytes(base64.b64decode(enc["iv"]), "big"))
    return AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(ct)


def _find_config(bot: Path):
    env = os.environ.get("CONFIG_FILE")
    candidates = [Path(env)] if env else [Path("config.toml"), Path("config") / "config.toml"]
    for path in candidates:
        path = path if path.is_absolute() else bot / path
        if path.is_file():
            return path
    return None


def _credentials(bot: Path):
    """Homeserver and token: the config's [matrix] section, else data/credentials.json
    (written by a bot's setup script), else data/access_token (bots that log in by password)."""
    matrix = {}
    config = _find_config(bot)
    if config is not None:
        try:
            matrix = tomllib.loads(config.read_text(encoding="utf-8")).get("matrix", {})
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise Abort(f"Can't read {config}: {exc}")
    stored = {}
    credentials = bot / "data" / "credentials.json"
    if credentials.is_file():
        try:
            stored = json.loads(credentials.read_text())
        except (OSError, ValueError) as exc:
            raise Abort(f"Can't read {credentials}: {exc}")
    homeserver = str(matrix.get("homeserver") or stored.get("homeserver") or "").rstrip("/")
    token = matrix.get("access_token") or stored.get("access_token") or ""
    token_file = bot / "data" / "access_token"
    if not token and token_file.is_file():
        token = token_file.read_text().strip()
    if not homeserver or not token:
        raise Abort(f"No homeserver or access token found for the bot in {bot} "
                    "(config, data/credentials.json or data/access_token). "
                    "Run this in the bot's directory, after the bot's setup or first start.")
    return homeserver, token


def _ask_recovery_key() -> str:
    return getpass.getpass("Recovery key (not shown): ")


def restore(homeserver: str, token: str, data: Path, ask_key=_ask_recovery_key, out=print) -> str:
    """Write data/cross_signing_keys.json from secret storage.

    Returns "restored"; "fresh" (the account has no cross-signing keys yet: the
    bot creates them on first start); "no_secret_storage" (the account has keys
    but no secret storage, so they can't be restored: only a reset helps); or
    "skipped" (ask_key returned an empty string). Raises Abort, with nothing
    changed, on any problem. Progress goes to out() (pass a no-op to print
    your own summary instead)."""

    def api(method, path, body=None):
        req = urllib.request.Request(
            homeserver + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                     "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code == 401:
                raise Abort("The homeserver rejected the bot's access token (logged out?).")
            raise Abort(f"{method} {path}: HTTP {exc.code}")
        except (urllib.error.URLError, OSError) as exc:
            raise Abort(f"Can't reach {homeserver}: {exc}")

    user_id = api("GET", "/_matrix/client/v3/account/whoami")["user_id"]

    def account_data(kind):
        return api("GET", f"/_matrix/client/v3/user/{urllib.parse.quote(user_id)}"
                          f"/account_data/{urllib.parse.quote(kind)}")

    default = account_data("m.secret_storage.default_key")
    if not default or "key" not in default:
        query = api("POST", "/_matrix/client/v3/keys/query", {"device_keys": {user_id: []}}) or {}
        has_keys = any(query.get(f"{name}_keys", {}).get(user_id) for name in SECRETS)
        return "no_secret_storage" if has_keys else "fresh"
    key_id = default["key"]
    desc = account_data(f"m.secret_storage.key.{key_id}") or {}
    out(f"{user_id}: secret storage key {key_id}")

    text = ask_key()
    if not text.strip():
        return "skipped"
    key = decode_recovery_key(text)
    if desc.get("iv") and desc.get("mac"):  # check the key before decrypting anything
        aes_key, mac_key = _derive(key, "")
        ctr = Counter.new(128, initial_value=int.from_bytes(base64.b64decode(desc["iv"]), "big"))
        ct = AES.new(aes_key, AES.MODE_CTR, counter=ctr).encrypt(b"\x00" * 32)
        if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), _b64_loose(desc["mac"])):
            raise Abort("Wrong recovery key for this account's secret storage.")

    query = api("POST", "/_matrix/client/v3/keys/query", {"device_keys": {user_id: []}}) or {}
    server_pub = {}
    for name in SECRETS:
        keys = query.get(f"{name}_keys", {}).get(user_id, {}).get("keys", {})
        server_pub[name] = next(iter(keys.values()), None)
    if not all(server_pub.values()):
        raise Abort("The server has no complete cross-signing key set for this account.")

    priv, pub = {}, {}
    for name, secret in SECRETS.items():
        stored = (account_data(secret) or {}).get("encrypted", {}).get(key_id)
        if not stored:
            raise Abort(f"Secret storage has no {secret} for key {key_id}.")
        priv[name] = _b64_loose(_decrypt(key, secret, stored).decode())
        pub[name] = cs._b64(bytes(SigningKey(priv[name]).verify_key))
        ok = pub[name] == server_pub[name]
        out(f"  {name}: {pub[name][:8]}… server {server_pub[name][:8]}… {'OK' if ok else 'MISMATCH'}")
        if not ok:
            raise Abort("Secret storage holds keys that don't match the server.")

    data.mkdir(parents=True, exist_ok=True)
    old = data / cs._KEYS_FILE
    if old.exists():
        stale = data / f"{cs._KEYS_FILE}.stale-{datetime.date.today():%Y%m%d}"
        old.rename(stale)
        stale.chmod(0o600)
        out(f"Old file kept as {stale.name}")
    cs.save_local_keys(data, cs.CrossSigningKeys(
        master_sk=priv["master"], self_signing_sk=priv["self_signing"], user_signing_sk=priv["user_signing"],
        master_pub=pub["master"], self_signing_pub=pub["self_signing"], user_signing_pub=pub["user_signing"]))
    out(f"Wrote {old} (mode 600). The bot signs its device with it on start.")
    return "restored"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    bot = Path(argv[0] if argv else ".").resolve()
    try:
        result = restore(*_credentials(bot), bot / "data")
        if result == "fresh":
            raise Abort("The account has no cross-signing keys yet: the bot creates them on first start.")
        if result == "no_secret_storage":
            raise Abort("The account has cross-signing keys but no secret storage (no recovery set up), "
                        "so they can't be restored. Replace them: start the bot once with "
                        f"{cs._ALLOW_RESET_ENV}=1.")
        if result == "skipped":
            raise Abort("No recovery key given.")
        print("Restart the bot if it is running.")
    except Abort as exc:
        print(f"{exc}\nNothing changed.", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Nothing changed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
