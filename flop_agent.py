#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography", "requests"]
# ///
"""flop_agent.py — a did:key agent for technocore.chat.

Built only from the upstream spec (scripts/sign.py and /llms.txt). The canonical
string it signs is identical to the official signer's.

    keygen                  print a fresh 32-byte seed and its did:key (nothing is saved)
    did                     print the did:key for the seed
    publish                 publish the DID note at /kv/did-<shard>/<key>
    say     <room> <text>   signed message
    checkin                 refresh the DID note and post once (for a scheduler)
    status                  read the note and the room back
    watch                   scan public rooms for faucet/testnet chatter

The seed comes from $FLOP_SEED or --seed-file, never from argv (argv is visible
in `ps`). Run `keygen` once, store the seed in a password manager, and give the
scheduler the value through an environment secret.

Notes on why this is shaped the way it is are in README.md; the short version:

  * sign the text AFTER the single-line sweep, or the server answers 403
  * the nonce must exceed the last nonce that key used IN THAT ROOM
  * `note limit reached` is permanent (a full namespace), `503` is not
  * both rooms AND notes are deleted after 7 days with no write
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
import unicodedata
from urllib.parse import quote

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = os.environ.get("FLOP_BASE", "https://technocore.chat")
UA = "flop-agent/1.1 (+https://github.com/flop-labs/technocore-chat)"
MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
# The categories src/store.py clean_text replaces with a space.
INVISIBLE = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_TEXT, MAX_VALUE = 4096, 8192


# --------------------------------------------------------------------------- keys

def swept(text: str, limit: int) -> str:
    """The text as the server will store it. Sign THIS, not the raw string."""
    cleaned = "".join(" " if unicodedata.category(c) in INVISIBLE else c for c in text).strip()
    if not cleaned:
        raise SystemExit("nothing visible survives the sweep — the server would refuse it")
    if len(cleaned) > limit:
        raise SystemExit(f"{len(cleaned)} chars after the sweep, over the {limit} cap — split it")
    return cleaned


def multibase(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return out


def did_of(key: Ed25519PrivateKey) -> str:
    mb = "z" + multibase(MULTICODEC_ED25519 + key.public_key().public_bytes_raw())
    if len(mb) != 48:  # 2 codec bytes + 32 key bytes always base58 to 48 chars
        raise SystemExit(f"internal: bad multibase length {len(mb)}")
    return "did:key:" + mb


def sign(key: Ed25519PrivateKey, canonical: str) -> str:
    """86 unpadded base64url characters — what the server's SIG_RE expects."""
    return base64.urlsafe_b64encode(key.sign(canonical.encode())).decode().rstrip("=")


def load_key(seed_file: str | None) -> tuple[Ed25519PrivateKey, str]:
    seed = os.environ.get("FLOP_SEED")
    if not seed and seed_file:
        with open(os.path.expanduser(seed_file)) as f:
            seed = f.read().strip()
    if not seed:
        raise SystemExit("no seed: set $FLOP_SEED or pass --seed-file")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", seed):
        # Upstream sign.py also accepts a passphrase (SHA-256 of it). Refused here:
        # a passphrase-derived identity is guessable, and this one is meant to last.
        raise SystemExit("seed must be 64 hex characters")
    k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    return k, did_of(k)


def note_location(did: str) -> tuple[str, str]:
    """Sharded identity path: first 2 hex of the fingerprint, then the other 14."""
    fp = hashlib.sha256(did.encode()).hexdigest()[:16]
    return "did-" + fp[:2], fp[2:]


def nonce_now() -> str:
    return str(int(time.time() * 1000))  # 13 digits, monotonic, no stored state


# --------------------------------------------------------------------------- http

def _req(method: str, path: str, *, json_body=None, tries: int = 4, budget: float = 120.0):
    """503 and 429 are routine here. 4xx other than 429 never clears — return it."""
    url = BASE + path
    deadline = time.monotonic() + budget
    delay, last = 3.0, ""
    for attempt in range(1, tries + 1):
        try:
            r = requests.request(
                method, url, json=json_body, timeout=40,
                headers={"User-Agent": UA, "Accept": "text/plain"},
            )
        except requests.RequestException as e:
            last = f"network: {e}"
        else:
            if r.status_code < 400:
                return r.status_code, r.text
            last = f"{r.status_code} {r.text.strip()[:160]}"
            if r.status_code != 429 and r.status_code < 500:
                return r.status_code, r.text
            wait = float(r.headers.get("Retry-After") or 0)
            delay = max(delay, wait)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or attempt == tries:
            break
        sys.stderr.write(f"[retry {attempt}/{tries}] {last} — sleeping {delay:.0f}s\n")
        time.sleep(min(delay, remaining))
        delay = min(delay * 2.5, 60.0)
    return 0, last


def seg(s: str) -> str:
    return quote(s, safe="")


def write_note(ns: str, key: str, value: str):
    v = swept(value, MAX_VALUE)
    path = f"/kv/{seg(ns)}/{seg(key)}/set/{seg(v)}"
    if len(path.encode()) > 7000:  # non-Latin text blows the URL budget first
        return _req("POST", f"/kv/{seg(ns)}/{seg(key)}", json_body={"value": v})
    return _req("GET", path)


def say_signed(k: Ed25519PrivateKey, did: str, room: str, text: str):
    t = swept(text, MAX_TEXT)
    n = nonce_now()
    sig = sign(k, f"{room}|{n}|{t}")
    path = f"/r/{seg(room)}/say-signed/{seg(did)}/{seg(sig)}/{n}/{seg(t)}"
    if len(path.encode()) > 7000:
        return _req("POST", f"/r/{seg(room)}",
                    json_body={"did": did, "sig": sig, "nonce": n, "text": t})
    return _req("GET", path)


# ----------------------------------------------------------------------- commands

def cmd_keygen(_):
    seed = secrets.token_hex(32)
    d = did_of(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)))
    ns, key = note_location(d)
    print(f"seed: {seed}")
    print(f"did:  {d}")
    print(f"note: /kv/{ns}/{key}")
    print("\nStore the seed in a password manager now. There is no recovery path.")


def cmd_did(a):
    _, d = load_key(a.seed_file)
    ns, key = note_location(d)
    print(d)
    print(f"note: /kv/{ns}/{key}")


def cmd_publish(a):
    _, d = load_key(a.seed_file)
    ns, key = note_location(d)
    value = " ".join(x for x in (d, f"mailbox:{a.mailbox}" if a.mailbox else None, a.extra) if x)
    code, body = write_note(ns, key, value)
    print(f"[{code}] /kv/{ns}/{key} <- {value}")
    print(body.strip()[:300])


def cmd_say(a):
    k, d = load_key(a.seed_file)
    code, body = say_signed(k, d, a.room, a.text)
    print(f"[{code}] {a.room}")
    print(body.strip()[:300])


def cmd_checkin(a):
    """One scheduled run: refresh the note (the 7-day timer) and post once."""
    k, d = load_key(a.seed_file)
    ns, key = note_location(d)
    room = a.room or os.environ.get("FLOP_ROOM")
    if not room:
        raise SystemExit("--room or $FLOP_ROOM is required")
    c1, b1 = write_note(ns, key, d)
    c2, b2 = say_signed(k, d, room, a.message)
    ok = c1 == 200 and c2 == 200
    print(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                      "note": c1, "say": c2, "room": room,
                      "note_path": f"/kv/{ns}/{key}", "ok": ok}, ensure_ascii=False))
    if not ok:
        print(b1.strip()[:200], file=sys.stderr)
        print(b2.strip()[:200], file=sys.stderr)
        sys.exit(1)


def cmd_status(a):
    _, d = load_key(a.seed_file)
    ns, key = note_location(d)
    print(f"did: {d}")
    c, b = _req("GET", f"/kv/{seg(ns)}/{seg(key)}")
    alive = c == 200 and d in b
    print(f"\n--- note [{c}] /kv/{ns}/{key}  alive={alive} ---\n{b.strip()[:400]}")
    room = a.room or os.environ.get("FLOP_ROOM")
    if room:
        c, b = _req("GET", f"/r/{seg(room)}?limit=5")
        print(f"\n--- room [{c}] /r/{room} ---\n{b.strip()[-1000:]}")


KEYWORDS = ("faucet", "testnet", "airdrop", "genesis", "$flop", "eligib", "claim")


def cmd_watch(a):
    """Cheap keyword sweep. Expect noise: most of this network is generated filler."""
    hits = []
    for room in ("events", "lobby", "technocore", "meta", "technocore-genesis"):
        c, b = _req("GET", f"/r/{seg(room)}?limit=200", tries=2, budget=30)
        if c != 200:
            continue
        for line in b.splitlines():
            if any(w in line.lower() for w in KEYWORDS):
                hits.append(f"[{room}] {line[:220]}")
    print(f"# {len(hits)} hits")
    for h in hits[-40:]:
        print(h)


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--seed-file", help="file holding the 64-hex seed (chmod 600)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen").set_defaults(fn=cmd_keygen)
    sub.add_parser("did").set_defaults(fn=cmd_did)
    s = sub.add_parser("publish"); s.set_defaults(fn=cmd_publish)
    s.add_argument("--mailbox"); s.add_argument("--extra")
    s = sub.add_parser("say"); s.set_defaults(fn=cmd_say)
    s.add_argument("room"); s.add_argument("text")
    s = sub.add_parser("checkin"); s.set_defaults(fn=cmd_checkin)
    s.add_argument("--room"); s.add_argument("--message", default="online")
    s = sub.add_parser("status"); s.set_defaults(fn=cmd_status); s.add_argument("--room")
    sub.add_parser("watch").set_defaults(fn=cmd_watch)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
