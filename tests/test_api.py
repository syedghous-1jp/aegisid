"""HTTP API tests (require: pip install -r requirements-dev.txt)."""

import unittest

from fastapi.testclient import TestClient

from aegisid.app import RateLimiter, create_app
from aegisid.core import AegisVerifier
from aegisid.crypto import b64d, generate_keypair

ADMIN = {"X-Admin-Token": "a-long-random-admin-secret"}


def make_client(rate_limit=0):
    priv, pub = generate_keypair()
    app = create_app(AegisVerifier(priv, pub), admin_token=ADMIN["X-Admin-Token"],
                     rate_limit=rate_limit)
    return TestClient(app)


class TestApi(unittest.TestCase):
    def setUp(self):
        self.c = make_client()
        self.c.post("/admin/batches", json={"batch_id": "B1", "region": "Karachi"}, headers=ADMIN)

    def issue(self, ttl=3600):
        r = self.c.post("/admin/issue", json={"batch_id": "B1", "ttl": ttl}, headers=ADMIN)
        self.assertEqual(r.status_code, 200)
        return r.json()

    def test_full_flow_issue_scan_replay(self):
        token = self.issue()
        ok = self.c.post("/scan", json={"token": token, "region": "Karachi", "challenge": "n1"})
        self.assertEqual(ok.status_code, 200)
        self.assertEqual((ok.json()["status"], ok.json()["challenge"]), ("GENUINE", "n1"))
        again = self.c.post("/scan", json={"token": token, "region": "Karachi"})
        self.assertEqual(again.status_code, 403)
        self.assertEqual(again.json()["detail"]["code"], "ALREADY_USED")

    def test_public_key_lets_a_client_verify_the_response(self):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        pub = load_pem_public_key(self.c.get("/public-key").json()["public_key_pem"].encode())
        res = self.c.post("/scan", json={"token": self.issue(), "region": "Karachi",
                                         "challenge": "c"}).json()
        from aegisid.crypto import verify_json
        payload = {k: v for k, v in res.items() if k != "sig"}
        self.assertTrue(verify_json(pub, payload, res["sig"]))

    def test_rejection_does_not_reveal_internal_details(self):
        r = self.c.post("/scan", json={"token": self.issue(), "region": "Dubai"})
        self.assertEqual(r.status_code, 403)
        text = r.text
        self.assertNotIn("Karachi", text)
        self.assertNotIn("layer", text.lower())

    def test_unknown_token_is_rejected(self):
        fake = {"v": 1, "pid": "p", "batch": "B1", "nonce": "n", "exp": 9999999999, "sig": "AAAA"}
        r = self.c.post("/scan", json={"token": fake, "region": "Karachi"})
        self.assertEqual((r.status_code, r.json()["detail"]["code"]), (403, "INVALID_TOKEN"))

    def test_schema_rejects_extra_fields_and_oversized_input(self):
        t = self.issue()
        self.assertEqual(self.c.post("/scan", json={"token": {**t, "x": 1}, "region": "Karachi"}).status_code, 422)
        self.assertEqual(self.c.post("/scan", json={"token": t, "region": "K" * 500}).status_code, 422)
        self.assertEqual(self.c.post("/scan", json={"token": t, "region": "Karachi", "challenge": "c" * 65}).status_code, 422)
        self.assertEqual(self.c.post("/scan", json={"token": "nope", "region": "Karachi"}).status_code, 422)

    def test_admin_endpoints_require_the_token(self):
        self.assertEqual(self.c.post("/admin/issue", json={"batch_id": "B1"}).status_code, 401)
        self.assertEqual(self.c.post("/admin/issue", json={"batch_id": "B1"},
                                     headers={"X-Admin-Token": "wrong"}).status_code, 401)
        self.assertEqual(self.c.get("/admin/audit").status_code, 401)

    def test_admin_api_is_disabled_when_no_token_is_configured(self):
        priv, pub = generate_keypair()
        c = TestClient(create_app(AegisVerifier(priv, pub), admin_token="", rate_limit=0))
        self.assertEqual(c.post("/admin/issue", json={"batch_id": "B1"}, headers=ADMIN).status_code, 503)

    def test_admin_input_validation(self):
        self.assertEqual(self.c.post("/admin/issue", json={"batch_id": "NOPE"}, headers=ADMIN).status_code, 404)
        self.assertEqual(self.c.post("/admin/issue", json={"batch_id": "B1", "ttl": 0}, headers=ADMIN).status_code, 422)
        self.assertEqual(self.c.post("/admin/batches", json={"batch_id": "B1", "region": "Dubai"}, headers=ADMIN).status_code, 409)

    def test_audit_endpoint_and_health_do_not_leak_to_the_public(self):
        self.c.post("/scan", json={"token": self.issue(), "region": "Karachi"})
        audit = self.c.get("/admin/audit", headers=ADMIN).json()
        self.assertEqual((audit["entries"], audit["intact"]), (1, True))
        self.assertEqual(self.c.get("/health").json(), {"status": "ok"})

    def test_scan_is_rate_limited(self):
        c = make_client(rate_limit=3)
        codes = [c.post("/scan", json={"token": {"v": 1, "pid": "p", "batch": "b", "nonce": "n",
                                                  "exp": 1, "sig": "s"}, "region": "r"}).status_code
                 for _ in range(5)]
        self.assertEqual(codes[:3], [403, 403, 403])
        self.assertEqual(codes[3:], [429, 429])


class TestRateLimiter(unittest.TestCase):
    def test_window_and_disable(self):
        rl = RateLimiter(2, window=60)
        self.assertEqual([rl.allow("a"), rl.allow("a"), rl.allow("a"), rl.allow("b")],
                         [True, True, False, True])
        off = RateLimiter(0)
        self.assertTrue(all(off.allow("a") for _ in range(100)))


if __name__ == "__main__":
    unittest.main()
