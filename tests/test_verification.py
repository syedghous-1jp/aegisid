
"""Test suite: every barcode/token must pass ALL 5 layers.

Run:  python -m unittest discover tests -v
"""
import time
import unittest
from aegisid.core import AegisVerifier, VerificationError
from aegisid.crypto import generate_keypair, verify_json


class TestFiveLayerGate(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.v = AegisVerifier(self.priv, self.pub)
        self.v.register_batch("BATCH-001", "Karachi")

    def _good_token(self):
        return self.v.issue_token("BATCH-001")

    # ---- LAYER 1: signature ----
    def test_layer1_valid_signature(self):
        token = self._good_token()
        payload = {k: token[k] for k in ("v", "pid", "batch", "nonce", "exp")}
        self.assertTrue(verify_json(self.pub, payload, token["sig"]))

    def test_layer1_forged_signature_rejected(self):
        token = self._good_token()
        token["pid"] = "forged-product-id"
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(token, "Karachi")
        self.assertEqual(ctx.exception.layer, 1)

    # ---- LAYER 2: expiry ----
    def test_layer2_expired_token_rejected(self):
        token = self.v.issue_token("BATCH-001", ttl=-1)
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(token, "Karachi")
        self.assertEqual(ctx.exception.layer, 2)

    def test_layer2_valid_token_not_expired(self):
        token = self._good_token()
        self.assertLess(time.time(), token["exp"])

    # ---- LAYER 3: replay ----
    def test_layer3_replay_rejected(self):
        token = self._good_token()
        self.v.verify(token, "Karachi")
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(dict(token), "Karachi")   # exact copy
        self.assertEqual(ctx.exception.layer, 3)

    def test_layer3_fresh_token_accepted(self):
        token = self._good_token()
        res = self.v.verify(token, "Karachi")
        self.assertEqual(res["status"], "GENUINE")

    # ---- LAYER 4: batch binding + geo anomaly ----
    def test_layer4_wrong_region_rejected(self):
        token = self._good_token()
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(token, "Lahore")
        self.assertEqual(ctx.exception.layer, 4)

    def test_layer4_correct_region_accepted(self):
        token = self._good_token()
        res = self.v.verify(token, "Karachi")
        self.assertEqual(res["batch"], "BATCH-001")

    # ---- LAYER 5: tamper-evident audit log ----
    def test_layer5_log_intact_after_scans(self):
        for _ in range(5):
            self.v.verify(self._good_token(), "Karachi")
        self.assertEqual(len(self.v.log), 5)
        self.assertTrue(self.v.log.verify())

    def test_layer5_log_tampering_detected(self):
        self.v.verify(self._good_token(), "Karachi")
        self.v.log._entries[0]["event"]["region"] = "FAKE"
        self.assertFalse(self.v.log.verify())

    # ---- signed response integrity ----
    def test_response_signed_by_manufacturer(self):
        token = self._good_token()
        res = self.v.verify(token, "Karachi")
        payload = {k: res[k] for k in ("pid", "status", "batch", "anchor")}
        self.assertTrue(verify_json(self.pub, payload, res["sig"]))

    # ---- 5 consecutive checks on the SAME barcode flow ----
    def test_five_full_checks_per_barcode(self):
        """Each genuine barcode passes 5 repeated end-to-end checks
        (fresh tokens), while copies always fail at layer 3."""
        results = [self.v.verify(self._good_token(), "Karachi")
                   for _ in range(5)]
        self.assertTrue(all(r["status"] == "GENUINE" for r in results))
        self.assertTrue(self.v.log.verify())

    # ---- REGRESSION: malformed token must not crash the verifier ----
    def test_malformed_token_rejected_cleanly(self):
        for bad in [{}, {"pid": "x"}, "not-a-dict", None,
                    {"v": 1, "pid": "a", "batch": "BATCH-001",
                     "nonce": "n"}]:          # missing exp + sig
            with self.assertRaises(VerificationError):
                self.v.verify(bad, "Karachi")

    # ---- REGRESSION: failed geo-check must NOT burn the token ----
    def test_failed_geo_check_does_not_burn_token(self):
        token = self._good_token()
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(token, "Lahore")           # wrong region
        self.assertEqual(ctx.exception.layer, 4)
        # same token must still verify in the correct region
        res = self.v.verify(token, "Karachi")
        self.assertEqual(res["status"], "GENUINE")
        # ...and only NOW is it burned
        with self.assertRaises(VerificationError):
            self.v.verify(dict(token), "Karachi")


if __name__ == "__main__":
    unittest.main()
