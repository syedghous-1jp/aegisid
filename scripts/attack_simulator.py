
"""Red-team attack simulator: proves each defense layer actually works.

Run:  python scripts/attack_simulator.py
"""
import sys
sys.path.insert(0, ".")
from aegisid.core import AegisVerifier, VerificationError
from aegisid.crypto import generate_keypair


def run():
    priv, pub = generate_keypair()
    v = AegisVerifier(priv, pub)
    v.register_batch("BATCH-ATK", "Karachi")
    results = []

    def attack(name, fn, expect_layer):
        try:
            fn()
            results.append((name, "FAILED - attack got through!", None))
        except VerificationError as exc:
            ok = "BLOCKED" if exc.layer == expect_layer else                      f"blocked at wrong layer ({exc.layer})"
            results.append((name, ok, exc.reason))

    # 1. Forged signature (attacker creates their own keypair)
    apriv, apub = generate_keypair()
    fake = AegisVerifier(apriv, apub).issue_token.__wrapped__ if False else None
    import copy as _copy
    t = v.issue_token("BATCH-ATK")
    forged = _copy.deepcopy(t)
    forged["pid"] = "fake"
    from aegisid.crypto import sign_json
    forged["sig"] = sign_json(apriv, {k: forged[k] for k in
                          ("v", "pid", "batch", "nonce", "exp")})
    attack("Forged signature", lambda: v.verify(forged, "Karachi"), 1)

    # 2. Expired token replay
    old = v.issue_token("BATCH-ATK", ttl=-10)
    attack("Expired token", lambda: v.verify(old, "Karachi"), 2)

    # 3. Copied barcode scanned twice
    copied = v.issue_token("BATCH-ATK")
    v.verify(copied, "Karachi")
    attack("Copied barcode (replay)",
           lambda: v.verify(dict(copied), "Karachi"), 3)

    # 4. Geo-anomaly (stolen stock scanned abroad)
    stolen = v.issue_token("BATCH-ATK")
    attack("Geo-anomaly scan", lambda: v.verify(stolen, "Dubai"), 4)

    # 5. Log tampering after a legit scan
    v.verify(v.issue_token("BATCH-ATK"), "Karachi")
    v.log._entries[-1]["event"]["pid"] = "hacked"
    results.append(("Audit-log tampering",
                    "BLOCKED" if not v.log.verify() else "FAILED - log editable!",
                    "hash chain broken"))

    print("\n" + "=" * 62)
    print("  AEGISID ATTACK SIMULATOR - RED TEAM RESULTS")
    print("=" * 62)
    all_ok = True
    for name, status, reason in results:
        flag = "✔" if status.startswith("BLOCKED") else "✘"
        if not status.startswith("BLOCKED"):
            all_ok = False
        print(f"  {flag} {name:28s} {status}")
        if reason:
            print(f"      ↳ {reason}")
    print("=" * 62)
    print(f"  VERDICT: {'ALL ATTACKS BLOCKED ✔' if all_ok else 'DEFENSE GAP FOUND ✘'}")
    print("=" * 62 + "\n")
    return all_ok


if __name__ == "__main__":
    import sys as _s
    _s.exit(0 if run() else 1)
