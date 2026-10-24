"""Hardening tests: persistence, concurrency, insider attacks, key binding."""

import hashlib
import json
import os
import tempfile
import threading
import unittest

from aegisid.core import AegisVerifier, VerificationError
from aegisid.crypto import (canonical_json, generate_keypair, load_or_create_private_key,
                            public_key_id)
from aegisid.store import GENESIS, Store


class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "aegis.db")
        self.key = os.path.join(self.tmp.name, "key.pem")

    def tearDown(self):
        self.tmp.cleanup()

    def boot(self):
        priv = load_or_create_private_key(self.key)
        return AegisVerifier(priv, priv.public_key(), Store(self.db))

    def test_issued_tokens_survive_a_restart(self):
        first = self.boot()
        first.register_batch("B1", "Karachi")
        token = first.issue_token("B1", ttl=3600)
        first.store.close()
        second = self.boot()                               # "restart"
        self.assertEqual(second.verify(token, "Karachi")["status"], "GENUINE")

    def test_replay_is_still_blocked_after_a_restart(self):
        first = self.boot()
        first.register_batch("B1", "Karachi")
        token = first.issue_token("B1", ttl=3600)
        first.verify(token, "Karachi")
        first.store.close()
        second = self.boot()
        with self.assertRaises(VerificationError) as ctx:
            second.verify(dict(token), "Karachi")
        self.assertEqual(ctx.exception.layer, 3)
        self.assertTrue(second.log.verify())

    def test_database_refuses_a_different_signing_key(self):
        first = self.boot()
        first.store.close()
        priv, pub = generate_keypair()
        with self.assertRaises(RuntimeError):
            AegisVerifier(priv, pub, Store(self.db))

    def test_key_file_is_created_with_private_permissions(self):
        load_or_create_private_key(self.key)
        if os.name == "posix":
            self.assertEqual(os.stat(self.key).st_mode & 0o777, 0o600)
        self.assertEqual(public_key_id(load_or_create_private_key(self.key).public_key()),
                         public_key_id(load_or_create_private_key(self.key).public_key()))


class TestConcurrency(unittest.TestCase):
    def test_simultaneous_scans_of_one_token_only_one_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            priv, pub = generate_keypair()
            v = AegisVerifier(priv, pub, Store(os.path.join(tmp, "c.db")))
            v.register_batch("B1", "Karachi")
            token = v.issue_token("B1", ttl=3600)
            results, barrier = [], threading.Barrier(16)

            def scan():
                barrier.wait()
                try:
                    v.verify(dict(token), "Karachi")
                    results.append("ok")
                except VerificationError as exc:
                    results.append(exc.code)

            threads = [threading.Thread(target=scan) for _ in range(16)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            self.assertEqual(results.count("ok"), 1)
            self.assertEqual(results.count("ALREADY_USED"), 15)
            self.assertEqual(len(v.log), 1)
            self.assertTrue(v.log.verify())


class TestInsiderAttacks(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = generate_keypair()
        self.v = AegisVerifier(self.priv, self.pub)
        self.v.register_batch("B1", "Karachi")
        for _ in range(3):
            self.v.verify(self.v.issue_token("B1"), "Karachi")

    def test_rewriting_the_whole_hash_chain_is_detected(self):
        """An insider with database access recomputes every hash after editing a record.
        The chain is then self-consistent, but the signatures no longer match."""
        db, prev = self.v.store._db, GENESIS
        rows = db.execute("SELECT seq, record FROM log ORDER BY seq").fetchall()
        for seq, record in rows:
            text = record.replace("Karachi", "Dubai") if seq == 1 else record
            rec = json.loads(text)
            rec["prev"] = prev
            text = canonical_json(rec).decode()
            digest = hashlib.sha256(text.encode()).hexdigest()
            db.execute("UPDATE log SET record=?, hash=? WHERE seq=?", (text, digest, seq))
            prev = digest
        self.assertFalse(self.v.log.verify())

    def test_forged_log_entry_without_the_key_is_detected(self):
        db = self.v.store._db
        text = canonical_json({"event": {"pid": "x"}, "prev": self.v.log.head, "ts": 1.0}).decode()
        digest = hashlib.sha256(text.encode()).hexdigest()
        db.execute("INSERT INTO log(record, hash, sig) VALUES (?, ?, ?)", (text, digest, "AAAA"))
        self.assertFalse(self.v.log.verify())

    def test_head_changes_with_every_scan_for_external_anchoring(self):
        before = self.v.log.head
        self.v.verify(self.v.issue_token("B1"), "Karachi")
        self.assertNotEqual(before, self.v.log.head)

    def test_truncating_the_newest_entries_is_only_visible_via_the_anchored_head(self):
        anchored = self.v.log.head
        self.v.store._db.execute("DELETE FROM log WHERE seq = 3")
        self.assertTrue(self.v.log.verify())              # chain still valid: documented limitation
        self.assertNotEqual(self.v.log.head, anchored)    # ...but the anchor reveals it


if __name__ == "__main__":
    unittest.main()
