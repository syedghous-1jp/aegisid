"""Attack simulator: shows that each defence behaves as documented.

Run:  python scripts/attack_simulator.py

Every scenario is expected to be stopped. Scenarios that AegisID cannot stop
by design (e.g. a counterfeiter who scans a copied label first) are described
in THREAT-MODEL.md instead of being hidden here.
"""

import copy
import hashlib
import json
import sys

sys.path.insert(0, ".")
from aegisid.core import AegisVerifier, VerificationError          # noqa: E402
from aegisid.crypto import (canonical_json, generate_keypair, sign_json,   # noqa: E402
                            verify_json)
from aegisid.store import GENESIS                                   # noqa: E402

TOKEN_KEYS = ("v", "pid", "batch", "nonce", "exp")


def run() -> bool:
    priv, pub = generate_keypair()
    v = AegisVerifier(priv, pub)
    v.register_batch("BATCH-ATK", "Karachi")
    results = []

    def expect_rejection(name, call, layer, code):
        try:
            call()
            results.append((name, False, "attack got through"))
        except VerificationError as exc:
            ok = (exc.layer, exc.code) == (layer, code)
            results.append((name, ok, f"layer {exc.layer} / {exc.code}"
                            + ("" if ok else f" (expected layer {layer} / {code})")))

    # 1. Forged signature: attacker signs a made-up token with their own key
    attacker_priv, _ = generate_keypair()
    t = v.issue_token("BATCH-ATK")
    forged = {**t, "pid": "fake"}
    forged["sig"] = sign_json(attacker_priv, {k: forged[k] for k in TOKEN_KEYS})
    expect_rejection("Forged signature", lambda: v.verify(forged, "Karachi"), 1, "INVALID_TOKEN")

    # 2. Field tampering: valid signature, edited product id
    tampered = {**v.issue_token("BATCH-ATK"), "pid": "other-product"}
    expect_rejection("Tampered token field", lambda: v.verify(tampered, "Karachi"), 1, "INVALID_TOKEN")

    # 3. Expired token
    old = v.issue_token("BATCH-ATK", ttl=-10)
    expect_rejection("Expired token", lambda: v.verify(old, "Karachi"), 2, "EXPIRED")

    # 4. Copied label: the second scan of the same token is rejected
    original = v.issue_token("BATCH-ATK")
    v.verify(original, "Karachi")
    expect_rejection("Copied label (second scan)",
                     lambda: v.verify(copy.deepcopy(original), "Karachi"), 3, "ALREADY_USED")

    # 5. Region mismatch (stolen stock scanned elsewhere, if the region is trustworthy)
    stolen = v.issue_token("BATCH-ATK")
    expect_rejection("Region mismatch", lambda: v.verify(stolen, "Dubai"), 4, "REGION_MISMATCH")

    # 6. Insider edits one audit record
    v.verify(v.issue_token("BATCH-ATK"), "Karachi")
    v.store._db.execute("UPDATE log SET record = replace(record, 'Karachi', 'Hacked') "
                        "WHERE seq = (SELECT MAX(seq) FROM log)")
    results.append(("Audit record edited", not v.log.verify(), "hash chain broken"))

    # 7. Insider rewrites the ENTIRE chain, recomputing every hash
    db, prev = v.store._db, GENESIS
    for seq, record in db.execute("SELECT seq, record FROM log ORDER BY seq").fetchall():
        rec = json.loads(record)
        rec["prev"] = prev
        text = canonical_json(rec).decode()
        digest = hashlib.sha256(text.encode()).hexdigest()
        db.execute("UPDATE log SET record=?, hash=? WHERE seq=?", (text, digest, seq))
        prev = digest
    results.append(("Whole audit chain rewritten", not v.log.verify(),
                    "signatures no longer match (needs the signing key)"))

    # 8. Fake "GENUINE" page replays a captured response to a different client
    v2 = AegisVerifier(priv, pub)
    v2.register_batch("BATCH-ATK", "Karachi")
    captured = v2.verify(v2.issue_token("BATCH-ATK"), "Karachi", challenge="victim-1")
    replayed = {k: val for k, val in captured.items() if k != "sig"}
    replayed["challenge"] = "victim-2"
    results.append(("Captured response replayed", not verify_json(pub, replayed, captured["sig"]),
                    "challenge is part of the signed payload"))

    print("\n" + "=" * 66)
    print("  AEGISID ATTACK SIMULATOR")
    print("=" * 66)
    all_ok = True
    for name, ok, detail in results:
        all_ok &= bool(ok)
        print(f"  {'[PASS]' if ok else '[FAIL]'} {name:30s} {detail}")
    print("=" * 66)
    print(f"  VERDICT: {'ALL SCENARIOS STOPPED' if all_ok else 'DEFENCE GAP FOUND'}")
    print("=" * 66 + "\n")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
