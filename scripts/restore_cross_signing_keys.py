#!/usr/bin/env python3
"""Restore a bot's cross-signing private keys from Matrix secret storage (4S).

For when <bot>/data/cross_signing_keys.json is stale (the account's keys were
reset later, e.g. from Element), so the bot can't sign new devices. Asks for the
account's recovery key (no echo), decrypts the three private keys from secret
storage, checks that they match the public keys on the server, keeps the old
file as cross_signing_keys.json.stale-<date> and writes the new one (mode 600).
Prints only public key prefixes. Doesn't restart the bot.

Usage (bot venv python, it has pycryptodome + pynacl):
    .venv/bin/python ../matrix-element-call-common/scripts/restore_cross_signing_keys.py <bot dir>
"""
import base64, datetime, getpass, hashlib, hmac, json, re, sys, urllib.parse, urllib.request
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util import Counter
from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from matrix_bot_common import cross_signing as cs  # noqa: E402

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECRETS = {"master": "m.cross_signing.master", "self_signing": "m.cross_signing.self_signing",
           "user_signing": "m.cross_signing.user_signing"}


def decode_recovery_key(text: str) -> bytes:
    s = re.sub(r"\s+", "", text)
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) != 35 or raw[:2] != b"\x8b\x01":
        sys.exit("That doesn't look like a recovery key (wrong length or prefix).")
    parity = 0
    for b in raw:
        parity ^= b
    if parity:
        sys.exit("Recovery key parity check failed (typo?).")
    return raw[2:34]


def derive(key: bytes, name: str):
    okm = HKDF(key, 64, b"\x00" * 32, SHA256, context=name.encode())
    return okm[:32], okm[32:]


def decrypt(key: bytes, name: str, enc: dict) -> bytes:
    aes_key, mac_key = derive(key, name)
    ct = base64.b64decode(enc["ciphertext"])
    if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), base64.b64decode(enc["mac"])):
        raise ValueError(f"bad MAC for {name}")
    ctr = Counter.new(128, initial_value=int.from_bytes(base64.b64decode(enc["iv"]), "big"))
    return AES.new(aes_key, AES.MODE_CTR, counter=ctr).decrypt(ct)


def b64_loose(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4))


bot = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else sys.exit(__doc__)
data = bot / "data"
cfg_text = next((p.read_text() for p in (bot / "config.toml", bot / "config" / "config.toml") if p.exists()), "")
hs = (re.search(r'^\s*homeserver\s*=\s*"([^"]+)"', cfg_text, re.M) or sys.exit("homeserver not found")).group(1).rstrip("/")
m = re.search(r'^\s*access_token\s*=\s*"([^"]+)"', cfg_text, re.M)
token = m.group(1) if m else (data / "access_token").read_text().strip()


def api(method, path, body=None):
    req = urllib.request.Request(hs + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


uid = api("GET", "/_matrix/client/v3/account/whoami")["user_id"]
acct = lambda t: api("GET", f"/_matrix/client/v3/user/{urllib.parse.quote(uid)}/account_data/{urllib.parse.quote(t)}")
key_id = acct("m.secret_storage.default_key")["key"]
desc = acct(f"m.secret_storage.key.{key_id}")
print(f"{uid}: secret storage key {key_id}")

key = decode_recovery_key(getpass.getpass("Recovery key: "))
if desc.get("iv") and desc.get("mac"):  # check the key before decrypting anything
    aes_key, mac_key = derive(key, "")
    ctr = Counter.new(128, initial_value=int.from_bytes(base64.b64decode(desc["iv"]), "big"))
    ct = AES.new(aes_key, AES.MODE_CTR, counter=ctr).encrypt(b"\x00" * 32)
    if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), b64_loose(desc["mac"])):
        sys.exit("Wrong recovery key for this account's secret storage. Nothing changed.")

q = api("POST", "/_matrix/client/v3/keys/query", {"device_keys": {uid: []}})
server_pub = {n: next(iter(q[f"{n}_keys"][uid]["keys"].values())) for n in SECRETS}
priv, pub = {}, {}
for n, secret in SECRETS.items():
    plain = decrypt(key, secret, acct(secret)["encrypted"][key_id])
    priv[n] = b64_loose(plain.decode())
    pub[n] = cs._b64(bytes(SigningKey(priv[n]).verify_key))
    ok = pub[n] == server_pub[n]
    print(f"  {n}: {pub[n][:8]}… server {server_pub[n][:8]}… {'OK' if ok else 'MISMATCH'}")
    if not ok:
        sys.exit("Secret storage holds keys that don't match the server. Nothing changed.")

old = data / cs._KEYS_FILE
if old.exists():
    stale = data / f"{cs._KEYS_FILE}.stale-{datetime.date.today():%Y%m%d}"
    old.rename(stale)
    stale.chmod(0o600)
    print(f"old file kept as {stale.name}")
cs.save_local_keys(data, cs.CrossSigningKeys(
    master_sk=priv["master"], self_signing_sk=priv["self_signing"], user_signing_sk=priv["user_signing"],
    master_pub=pub["master"], self_signing_pub=pub["self_signing"], user_signing_pub=pub["user_signing"]))
print(f"wrote {data / cs._KEYS_FILE} (600). Restart the bot to use it.")
