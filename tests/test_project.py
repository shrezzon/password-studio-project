"""Meaningful checks for the analyzer, generator, vault, and web flow.

Run from the project folder: python -m unittest discover -s tests -v
"""
import base64
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import InvalidToken

import app as web
import security


class PasswordTests(unittest.TestCase):
    def test_offline_list_and_patterns(self):
        self.assertGreaterEqual(len(set(security.COMMON_PASSWORDS)), 1000)
        for password, fragment in [("password", "common-password"), ("qwerty!", "sequence"),
                                   ("aaaXYZ!", "repeated"), ("Rahul1999!", "year"),
                                   ("Rahul1999!", "name"), ("Coffee!84", "dictionary")]:
            result = security.analyze_password(password)
            self.assertTrue(any(fragment in warning for warning in result["warnings"]), password)
        self.assertEqual(security.analyze_password("password")["label"], "Very weak")
        self.assertIsNone(security.analyze_password("naïve!42")["entropy"])

    def test_random_generator_respects_selected_types(self):
        for _ in range(30):
            generated = security.generate_password(24, ["lowercase", "uppercase", "digits", "symbols"])
            self.assertEqual(len(generated), 24)
            for chars in security.CHARACTER_GROUPS.values():
                self.assertTrue(any(char in chars for char in generated))
        with self.assertRaises(ValueError):
            security.generate_password(20, [])
        with self.assertRaises(ValueError):
            security.generate_password(3, ["digits"])

    def test_real_encryption_and_tamper_detection(self):
        data, key = security.new_vault("Example master passphrase 72!")
        entries = [{"site": "DemoEmail", "username": "example-user", "password": "ExampleSecret!42"}]
        ciphertext = security.encrypt_entries(entries, key)
        self.assertNotIn("ExampleSecret!42", ciphertext)
        self.assertNotEqual(data["auth_salt"], data["vault_salt"])
        self.assertTrue(security.verify_master("Example master passphrase 72!", data))
        self.assertFalse(security.verify_master("incorrect master", data))
        self.assertEqual(security.decrypt_entries(ciphertext, key), entries)
        wrong_key = security.vault_key("incorrect master", data)
        with self.assertRaises(InvalidToken):
            security.decrypt_entries(ciphertext, wrong_key)
        raw = bytearray(base64.urlsafe_b64decode(ciphertext))
        raw[-1] ^= 1
        modified = base64.urlsafe_b64encode(raw).decode("ascii")
        with self.assertRaises(InvalidToken):
            security.decrypt_entries(modified, key)


class WebFlowTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.old_path = web.VAULT_FILE
        web.VAULT_FILE = Path(self.folder.name) / "test_vault.json"
        web.active_vaults.clear()
        web.app.config.update(TESTING=True)
        self.client = web.app.test_client()
        self.client.get("/vault")
        with self.client.session_transaction() as state:
            self.csrf = state["csrf_token"]

    def tearDown(self):
        web.VAULT_FILE = self.old_path
        web.active_vaults.clear()
        self.folder.cleanup()

    def post(self, route, values):
        return self.client.post(route, data={"csrf_token": self.csrf, **values}, follow_redirects=True)

    def create(self):
        response = self.post("/vault/create", {"master": "Demo master phrase 72!", "confirm": "Demo master phrase 72!"})
        self.assertIn(b"Vault created and unlocked", response.data)

    def test_create_add_reopen_and_delete(self):
        self.create()
        response = self.post("/vault/add", {"site": "Example Email", "username": "sample-user-72", "password": "DemoSecret!348"})
        self.assertIn(b"Credential saved", response.data)
        raw = web.VAULT_FILE.read_text()
        for plaintext in ("Example Email", "sample-user-72", "DemoSecret!348", "Demo master phrase 72!"):
            self.assertNotIn(plaintext, raw)
        self.post("/vault/lock", {})
        self.assertIn(b"Unlock your vault", self.client.get("/vault").data)
        response = self.post("/vault/login", {"master": "Demo master phrase 72!"})
        self.assertIn(b"DemoSecret!348", response.data)
        data = json.loads(raw)
        key = security.vault_key("Demo master phrase 72!", data)
        entry_id = security.decrypt_entries(data["ciphertext"], key)[0]["id"]
        self.assertIn(b"Credential deleted", self.post("/vault/delete", {"entry_id": entry_id}).data)
        self.assertNotIn(b"DemoSecret!348", self.client.get("/vault").data)

    def test_lockout_and_expiry_persist_in_file(self):
        self.create()
        self.post("/vault/lock", {})
        for _ in range(3):
            response = self.post("/vault/login", {"master": "wrong"})
        self.assertIn(b"Three incorrect attempts", response.data)
        data = json.loads(web.VAULT_FILE.read_text())
        self.assertEqual(data["failed_attempts"], 3)
        self.assertGreater(data["locked_until"], time.time() + 25)
        self.assertIn(b"Too many attempts", self.post("/vault/login", {"master": "Demo master phrase 72!"}).data)
        data["locked_until"] = time.time() - 1
        web.save_vault(data)
        self.assertIn(b"Vault unlocked", self.post("/vault/login", {"master": "Demo master phrase 72!"}).data)

    def test_form_protection_and_expiry(self):
        self.assertEqual(self.client.post("/vault/create", data={"master": "anything"}).status_code, 403)
        self.assertEqual(self.client.post("/vault/create", data={"csrf_token": "invalid-é"}).status_code, 403)
        self.assertEqual(self.client.get("/", headers={"Host": "attacker.example"}).status_code, 403)
        self.create()
        response = self.post("/vault/add", {"site": "<script>alert(1)</script>",
                                            "username": "example", "password": "Example!123"})
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", response.data)
        self.assertNotIn(b"<script>alert(1)</script>", response.data)
        with self.client.session_transaction() as state:
            token = state["vault_token"]
        web.active_vaults[token]["last_active"] = time.time() - web.IDLE_SECONDS - 1
        self.assertIn(b"Unlock your vault", self.client.get("/vault").data)

    def test_read_and_write_pages(self):
        self.assertEqual(self.client.get("/generator").status_code, 200)
        self.assertEqual(self.client.get("/demonstration").status_code, 200)
        self.assertIn(b"Analysis result", self.post("/", {"password": "Rahul1999!"}).data)
        self.assertIn(b"Your password", self.post("/generator", {"length": "20", "groups": ["lowercase", "digits"]}).data)


if __name__ == "__main__":
    unittest.main()
