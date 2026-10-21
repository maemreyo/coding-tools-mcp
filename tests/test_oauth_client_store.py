from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from coding_tools_mcp.oauth import OAuthClientRegistry

META = {
    "redirect_uris": ["https://chatgpt.com/connector/oauth/abc"],
    "token_endpoint_auth_method": "client_secret_post",
    "client_name": "ChatGPT",
}


class OAuthClientStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "state" / "oauth-clients.json"

    def test_registered_client_survives_restart(self) -> None:
        registered = OAuthClientRegistry(self.path).register(META)
        second = OAuthClientRegistry(self.path)
        client_id = registered["client_id"]
        self.assertIsNotNone(second.get(client_id))
        self.assertTrue(second.accepts_redirect(client_id, META["redirect_uris"][0]))
        self.assertTrue(second.authenticates(client_id, registered["client_secret"], "client_secret_post"))
        self.assertFalse(second.authenticates(client_id, "wrong", "client_secret_post"))

    def test_store_holds_digest_not_secret_and_is_private(self) -> None:
        registered = OAuthClientRegistry(self.path).register(META)
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn(registered["client_secret"], text)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_public_client_survives_restart(self) -> None:
        registered = OAuthClientRegistry(self.path).register({"redirect_uris": META["redirect_uris"]})
        second = OAuthClientRegistry(self.path)
        self.assertTrue(second.authenticates(registered["client_id"], "", "none"))

    def test_preregistered_clients_are_not_persisted(self) -> None:
        registry = OAuthClientRegistry(self.path)
        registry.add_preregistered("fixed", ("https://chatgpt.com/cb",), client_secret=None)
        registry.register(META)
        stored = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn("fixed", [c["client_id"] for c in stored["clients"]])
        self.assertIsNone(OAuthClientRegistry(self.path).get("fixed"))

    def test_without_store_nothing_is_written(self) -> None:
        registry = OAuthClientRegistry()
        self.assertIsNotNone(registry.get(registry.register(META)["client_id"]))
        self.assertFalse(self.path.exists())

    def test_corrupt_store_is_kept_aside_and_registry_starts_empty(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{not json", encoding="utf-8")
        registry = OAuthClientRegistry(self.path)
        self.assertEqual(len(list(self.path.parent.glob("oauth-clients.json.corrupt-*"))), 1)
        self.assertIsNotNone(registry.get(registry.register(META)["client_id"]))

    def test_invalid_entries_are_skipped(self) -> None:
        good = OAuthClientRegistry(self.path).register(META)["client_id"]
        document = json.loads(self.path.read_text(encoding="utf-8"))
        document["clients"].append({
            "client_id": "bad",
            "redirect_uris": ["http://evil.example/cb"],
            "token_endpoint_auth_method": "none",
            "issued_at": 1,
        })
        self.path.write_text(json.dumps(document), encoding="utf-8")
        reloaded = OAuthClientRegistry(self.path)
        self.assertIsNotNone(reloaded.get(good))
        self.assertIsNone(reloaded.get("bad"))

    def test_persist_failure_rolls_back_registration(self) -> None:
        registry = OAuthClientRegistry(self.path)
        with mock.patch("coding_tools_mcp.oauth.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError):
                registry.register(META)
        self.assertEqual(registry._clients, {})
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
