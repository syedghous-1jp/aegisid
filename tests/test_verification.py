"""The five-layer gate: every token must pass ALL layers.

Run:  python -m unittest discover tests -v
"""

import copy
import time
import unittest

from aegisid.core import AegisVerifier, VerificationError
from aegisid.crypto import generate_keypair, verify_json

TOKEN_KEYS = ("v", "pid", "batch", "nonce", "exp")
RESPONSE_UNSIGNED = ("pid", "status", "batch", "anchor", "ts", "challenge")


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.v = AegisVerifier(self.priv, self.pub)
        self.v.register_batch("BATCH-001", "Karachi")

    def good_token(self, **kw):
        return self.v.issue_token("BATCH-001", **kw)

    def reject(self, token, region="Karachi", **kw):
        with self.assertRaises(VerificationError) as ctx:
            self.v.verify(token, region, **kw)
        return ctx.exception


class TestFiveLayerGate(GateTestCase):
    # ---- LAYER 1: signature ----
    def test_layer1_valid_signature(self):
        token = self.good_token()
        self.assertTrue(verify_json(self.pub, {k: token[k] for k in TOKEN_KEYS}, token["sig"]))

    def test_layer1_forged_signature_rejected(self):
        token = self.good_token()
        token["pid"] = "forged-product-id"
        self.assertEqual(self.reject(token).layer, 1)

    def test_layer1_token_signed_by_another_key_rejected(self):
        other_priv, other_pub = generate_keypair()
        other = AegisVerifier(other_priv, other_pub)
        other.register_batch("BATCH-001", "Karachi")
        self.assertEqual(self.reject(other.issue_token("BATCH-001")).layer, 1)

    # ---- LAYER 2: expiry ----
    def test_layer2_expired_token_rejected(self):
        exc = self.reject(self.good_token(ttl=-1))
        self.assertEqual((exc.layer, exc.code), (2, "EXPIRED"))

    def test_layer2_valid_token_not_expired(self):
        self.assertLess(time.time(), self.good_token()["exp"])

    # ---- LAYER 3: replay ----
    def test_layer3_replay_rejected(self):
        token = self.good_token()
        self.v.verify(token, "Karachi")
        exc = self.reject(dict(token))
        self.assertEqual((exc.layer, exc.code), (3, "ALREADY_USED"))

    def test_layer3_fresh_token_accepted(self):
        self.assertEqual(self.v.verify(self.good_token(), "Karachi")["status"], "GENUINE")

    # ---- LAYER 4: batch binding + region ----
    def test_layer4_wrong_region_rejected(self):
        exc = self.reject(self.good_token(), "Lahore")
        self.assertEqual((exc.layer, exc.code), (4, "REGION_MISMATCH"))

    def test_layer4_correct_region_accepted(self):
        self.assertEqual(self.v.verify(self.good_token(), "Karachi")["batch"], "BATCH-001")

    def test_layer4_region_match_ignores_case_and_spacing(self):
        self.assertEqual(self.v.verify(self.good_token(), "  karachi ")["status"], "GENUINE")

    def test_layer4_unknown_product_rejected(self):
        # a correctly signed token for a product this database never issued
        other = AegisVerifier(self.priv, self.pub)         # same key, empty database
        other.register_batch("BATCH-001", "Karachi")
        self.assertEqual(self.reject(other.issue_token("BATCH-001")).layer, 4)

    # ---- LAYER 5: tamper-evident, signed audit log ----
    def test_layer5_log_intact_after_scans(self):
        for _ in range(5):
            self.v.verify(self.good_token(), "Karachi")
        self.assertEqual(len(self.v.log), 5)
        self.assertTrue(self.v.log.verify())

    def test_layer5_single_record_edit_detected(self):
        self.v.verify(self.good_token(), "Karachi")
        self.v.store._db.execute("UPDATE log SET record = replace(record, 'Karachi', 'FAKE')")
        self.assertFalse(self.v.log.verify())

    def test_layer5_deleted_record_detected(self):
        for _ in range(3):
            self.v.verify(self.good_token(), "Karachi")
        self.v.store._db.execute("DELETE FROM log WHERE seq = 2")
        self.assertFalse(self.v.log.verify())

    # ---- signed response ----
    def test_response_signed_by_manufacturer(self):
        res = self.v.verify(self.good_token(), "Karachi")
        self.assertTrue(verify_json(self.pub, {k: res[k] for k in RESPONSE_UNSIGNED}, res["sig"]))

    def test_response_is_bound_to_the_client_challenge(self):
        res = self.v.verify(self.good_token(), "Karachi", challenge="abc123")
        self.assertEqual(res["challenge"], "abc123")
        tampered = {k: res[k] for k in RESPONSE_UNSIGNED}
        tampered["challenge"] = "other-client"
        self.assertFalse(verify_json(self.pub, tampered, res["sig"]))

    def test_oversized_challenge_rejected(self):
        with self.assertRaises(ValueError):
            self.v.verify(self.good_token(), "Karachi", challenge="x" * 65)

    # ---- repeated flows ----
    def test_five_full_checks_per_product_flow(self):
        results = [self.v.verify(self.good_token(), "Karachi") for _ in range(5)]
        self.assertTrue(all(r["status"] == "GENUINE" for r in results))
        self.assertTrue(self.v.log.verify())


class TestRegressions(GateTestCase):
    def test_malformed_token_rejected_cleanly(self):
        for bad in [{}, {"pid": "x"}, "not-a-dict", None, [], 42,
                    {"v": 1, "pid": "a", "batch": "BATCH-001", "nonce": "n"}]:
            with self.subTest(bad=bad):
                self.assertEqual(self.reject(bad).layer, 1)

    def test_wrong_field_types_rejected_cleanly(self):
        token = self.good_token()
        for field, value in (("exp", "soon"), ("exp", True), ("v", "1"),
                             ("pid", 123), ("nonce", None), ("sig", 5)):
            bad = {**token, field: value}
            with self.subTest(field=field, value=value):
                self.assertEqual(self.reject(bad).layer, 1)

    def test_unsupported_token_version_rejected(self):
        from aegisid.crypto import sign_json
        t = self.good_token()
        payload = {**{k: t[k] for k in TOKEN_KEYS}, "v": 2}
        forged = {**payload, "sig": sign_json(self.priv, payload)}   # validly signed, wrong version
        self.assertEqual(self.reject(forged).layer, 1)

    def test_failed_region_check_does_not_burn_token(self):
        token = self.good_token()
        self.assertEqual(self.reject(token, "Lahore").layer, 4)
        self.assertEqual(self.v.verify(token, "Karachi")["status"], "GENUINE")
        self.assertEqual(self.reject(dict(token)).layer, 3)

    def test_non_string_region_rejected(self):
        self.assertEqual(self.reject(self.good_token(), None).layer, 4)

    def test_client_message_does_not_leak_expected_region(self):
        exc = self.reject(self.good_token(), "Dubai")
        self.assertNotIn("Karachi", exc.public_message)
        self.assertIn("Karachi", exc.reason)               # kept for server logs only

    def test_unknown_batch_cannot_be_issued(self):
        with self.assertRaises(ValueError):
            self.v.issue_token("NOPE")

    def test_batch_region_cannot_be_silently_changed(self):
        self.v.register_batch("BATCH-001", "Karachi")      # idempotent
        with self.assertRaises(ValueError):
            self.v.register_batch("BATCH-001", "Dubai")

    def test_copy_of_token_does_not_share_state_with_original(self):
        token = self.good_token()
        clone = copy.deepcopy(token)
        self.v.verify(token, "Karachi")
        self.assertEqual(self.reject(clone).layer, 3)


if __name__ == "__main__":
    unittest.main()
