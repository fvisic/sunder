"""The routes beyond the core handoff surface: consent, data-subject rights,
value tokenization, the file vault, shares, links, version history, external
claims and the admin unlock.

Each test asserts the wire contract and the properties a client can get
wrong: an empty cascade must not be sent as an opt-in, bulk routes must
carry the unlock token, and destructive calls are never blind-retried.
"""

import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sunder_client


class MockHandler(http.server.BaseHTTPRequestHandler):
    """Replays queued responses; records the raw body AND the headers, which
    the multipart upload and the unlock-gated routes are asserted on."""

    server_version = "SunderMock/0"

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None  # multipart, not JSON
        self.server.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": parsed,
            "raw": raw,
        })
        if self.server.responses:
            status, payload = self.server.responses.pop(0)
        else:
            status, payload = 500, {"error": "internal"}
        if isinstance(payload, dict | list):
            data = json.dumps(payload).encode("utf-8")
            ctype = "application/json"
        elif isinstance(payload, bytes):
            data = payload
            ctype = "application/octet-stream"
        else:
            data = str(payload).encode("utf-8")
            ctype = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_DELETE = _serve

    def log_message(self, *args):
        pass


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        cls.server.requests = []
        cls.server.responses = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.requests.clear()
        self.server.responses.clear()
        self.client = sunder_client.SunderClient(url=self.url,
                                                 credential="client_id.secret")

    def queue(self, *responses):
        self.server.responses.extend(responses)

    def only(self):
        self.assertEqual(len(self.server.requests), 1,
                         "expected exactly one request, saw "
                         f"{len(self.server.requests)}")
        return self.server.requests[0]

    # -- consent ------------------------------------------------------------

    def test_set_consent_sends_a_real_boolean(self):
        self.queue((200, {"cid": "CID1", "purpose": "billing", "granted": False}))
        out = self.client.set_consent("CID1", "billing", 0)
        self.assertIs(out["granted"], False)
        # A falsy int must reach the server as JSON false, not 0.
        self.assertIs(self.only()["body"]["granted"], False)

    def test_get_consent_returns_the_list(self):
        self.queue((200, {"consents": [{"purpose": "billing", "granted": True}]}))
        got = self.client.get_consent("CID1")
        self.assertEqual(len(got), 1)
        self.assertEqual(self.only()["path"], "/v1/consent/CID1")

    # -- data subject rights -------------------------------------------------

    def test_dsr_access_carries_holdings_beyond_the_blob(self):
        self.queue((200, {
            "scopes": [{
                "scope": "crm", "cid": "CID1",
                "attributes": {"email": "a@b.c"},
                "value_tokens": [{"token": "tok_1", "type": "card"}],
                "files": [{"id": "f1", "name": "scan.pdf"}],
                "shares": [{"uuid": "u1", "partner_label": "partner-bank"}],
                "links": [{"cid": "CID2", "link_type": "guardian", "role": "parent"}],
            }],
            "audit_trail": [{"ts": "2026-01-01T00:00:00Z", "client_id": "crm",
                             "user_id": "agent-7", "action": "lookup", "count": 3}],
        }))
        got = self.client.dsr_access("CID1")
        scope = got["scopes"][0]
        for section in ("value_tokens", "files", "shares", "links"):
            self.assertEqual(len(scope[section]), 1, f"{section} was dropped")
        # The share's recipient label IS the Article 15 answer.
        self.assertEqual(scope["shares"][0]["partner_label"], "partner-bank")
        self.assertIn("cid=CID1", self.only()["path"])

    def test_dsr_export_is_caller_scope_only(self):
        self.queue((200, {"scope": "crm", "cid": "CID1", "attributes": {}}))
        got = self.client.dsr_export("CID1")
        self.assertEqual(got["scope"], "crm")
        self.assertTrue(self.only()["path"].startswith("/v1/dsr/export?cid="))

    def test_erase_omits_cascade_unless_asked(self):
        self.queue((200, {"erasure_id": 7, "scopes": 2,
                          "linked": [{"cid": "CID2", "link_type": "guardian",
                                      "cascaded": False}]}))
        got = self.client.dsr_erase("CID1")
        self.assertEqual(got["erasure_id"], 7)
        self.assertNotIn("cascade", self.only()["body"],
                         "no cascade was requested, so the key must be absent")

    def test_erase_forwards_named_link_types(self):
        self.queue((200, {"erasure_id": 8, "scopes": 1}))
        self.client.dsr_erase("CID1", ["guardian"])
        self.assertEqual(self.only()["body"]["cascade"], ["guardian"])

    def test_erase_with_an_empty_list_sends_no_cascade(self):
        self.queue((200, {"erasure_id": 9, "scopes": 1}))
        self.client.dsr_erase("CID1", [])
        self.assertNotIn("cascade", self.only()["body"])

    def test_erase_is_never_retried(self):
        self.queue((503, {"error": "service_unavailable"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.dsr_erase("CID1")
        self.assertEqual(len(self.server.requests), 1,
                         "a destructive call must be attempted exactly once")

    # -- value tokenization ---------------------------------------------------

    def test_tokenize_omits_an_unset_cid(self):
        self.queue((201, {"token": "tok_abc"}))
        token = self.client.tokenize("4111111111111111", type="card", unique=True)
        self.assertEqual(token, "tok_abc")
        body = self.only()["body"]
        self.assertNotIn("cid", body, "an unset cid must be omitted, not sent empty")
        self.assertIs(body["unique"], True)

    def test_tokenize_binds_the_cid_when_given(self):
        self.queue((201, {"token": "tok_1"}))
        self.client.tokenize("x", cid="CID1")
        # The binding is what makes erasure destroy the token.
        self.assertEqual(self.only()["body"]["cid"], "CID1")

    def test_detokenize_and_delete(self):
        self.queue((200, {"value": "secret"}))
        self.assertEqual(self.client.detokenize("tok_1"), "secret")
        self.server.requests.clear()
        self.queue((200, {"status": "deleted"}))
        self.client.delete_token("tok_1")
        self.assertEqual(self.only()["method"], "DELETE")

    def test_delete_token_is_not_retried(self):
        self.queue((503, {"error": "service_unavailable"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.delete_token("tok_1")
        self.assertEqual(len(self.server.requests), 1)

    def test_bulk_routes_carry_the_unlock_token(self):
        self.queue((201, {"tokens": ["t1", "t2"]}))
        got = self.client.tokenize_bulk("unlock_xyz", [{"value": "a"}, {"value": "b"}])
        self.assertEqual(got, ["t1", "t2"])
        self.assertEqual(self.only()["headers"].get("X-Sunder-Unlock"), "unlock_xyz")

    def test_bulk_read_is_not_retried(self):
        # The unlock token is spent by the first attempt: a retry would come
        # back already-used and hide whether the batch landed.
        self.queue((503, {"error": "service_unavailable"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.detokenize_bulk("unlock_xyz", ["t1"])
        self.assertEqual(len(self.server.requests), 1)

    # -- file vault -----------------------------------------------------------

    def test_upload_sends_multipart_with_filename_and_expiry(self):
        self.queue((201, {"id": "f1", "name": "scan.pdf", "sha256": "deadbeef"}))
        meta = self.client.upload_file("CID1", "scan.pdf", b"hello",
                                       content_type="application/pdf",
                                       expires_at="2030-01-02T03:04:05Z")
        self.assertEqual(meta["sha256"], "deadbeef")
        req = self.only()
        self.assertTrue(req["headers"]["Content-Type"].startswith("multipart/form-data"))
        self.assertIn(b'filename="scan.pdf"', req["raw"])
        self.assertIn(b"hello", req["raw"])
        self.assertEqual(req["headers"].get("X-Sunder-File-Expiry"),
                         "2030-01-02T03:04:05Z")

    def test_upload_omits_the_expiry_header_when_none(self):
        self.queue((201, {"id": "f1"}))
        self.client.upload_file("CID1", "a.txt", b"x")
        self.assertIsNone(self.only()["headers"].get("X-Sunder-File-Expiry"))

    def test_list_files_sends_the_purpose(self):
        self.queue((200, {"files": [{"id": "f1"}]}))
        got = self.client.list_files("CID1", "support")
        self.assertEqual(got[0]["id"], "f1")
        self.assertIn("purpose=support", self.only()["path"])

    def test_download_returns_bytes_and_maps_errors(self):
        self.queue((200, b"raw-bytes"))
        self.assertEqual(self.client.download_file("f1", "support"), b"raw-bytes")
        self.server.requests.clear()
        # A 404 must not reach the caller as bytes of an error page.
        self.queue((404, {"error": "not_found"}))
        with self.assertRaises(sunder_client.NotFoundError):
            self.client.download_file("missing", "support")

    # -- shares, links, versions ----------------------------------------------

    def test_create_share_sends_the_partner_label(self):
        self.queue((201, {"uuid": "u1", "expires_at": "2026-01-01T00:00:00Z"}))
        got = self.client.create_share("CID1", ["email"],
                                       partner_label="partner-bank",
                                       purpose="kyc", ttl_seconds=3600)
        self.assertEqual(got["uuid"], "u1")
        self.assertEqual(self.only()["body"]["partner_label"], "partner-bank")

    def test_fetch_and_revoke_share(self):
        self.queue((200, {"fields": {"email": "a@b.c"}}))
        self.assertEqual(self.client.fetch_share("u1"), {"email": "a@b.c"})
        self.server.requests.clear()
        self.queue((200, {"status": "revoked"}))
        self.client.revoke_share("u1")
        self.assertEqual(self.only()["method"], "DELETE")

    def test_links_round_trip(self):
        self.queue((201, {"status": "linked"}))
        self.client.link("PARENT", "CHILD", "guardian")
        self.assertEqual(self.only()["body"]["link_type"], "guardian")
        self.server.requests.clear()
        self.queue((200, {"links": [{"cid": "CHILD", "link_type": "guardian",
                                     "role": "parent"}]}))
        links = self.client.list_links("PARENT")
        self.assertEqual(links[0]["role"], "parent")
        self.server.requests.clear()
        self.queue((200, {"status": "unlinked"}))
        self.client.unlink("PARENT", "CHILD")
        self.assertEqual(self.only()["method"], "DELETE")

    def test_historical_read_still_sends_the_purpose(self):
        self.queue((200, {"versions": [{"version_no": 2, "written_by": "crm"}]}))
        self.assertEqual(self.client.list_versions("CID1")[0]["version_no"], 2)
        self.server.requests.clear()
        self.queue((200, {"value": "old@example.com"}))
        got = self.client.get_version_attribute("CID1", 2, "email", "support")
        self.assertEqual(got, "old@example.com")
        # An old value is not a lesser secret.
        self.assertEqual(self.only()["path"],
                         "/v1/contacts/CID1/versions/2/attributes/email?purpose=support")

    # -- claims, unlock, attribution -------------------------------------------

    def test_external_claim_keeps_issuer_provenance(self):
        self.queue((200, {"stored": ["verified_age@gov-id"]}))
        stored = self.client.store_external_claim("CID1", "eyJ...envelope")
        self.assertIn("@", stored[0])
        self.assertEqual(self.only()["body"]["envelope"], "eyJ...envelope")

    def test_unlock_mints_a_single_use_token(self):
        self.queue((201, {"unlock_token": "unlock_xyz",
                          "expires_at": "2026-01-01T00:01:00Z"}))
        got = self.client.unlock("tokens")
        self.assertEqual(got["unlock_token"], "unlock_xyz")
        self.assertEqual(self.only()["body"]["purpose"], "tokens")

    def test_user_id_is_sent_on_every_call(self):
        client = sunder_client.SunderClient(url=self.url,
                                            credential="client_id.secret",
                                            user_id="agent-7")
        self.queue((200, {"value": "a@b.c"}))
        client.get_attribute("CID1", "email", "support")
        self.assertEqual(self.only()["headers"].get("X-Sunder-User-Id"), "agent-7")

    def test_ready_probe(self):
        self.queue((200, "ok"))
        self.assertEqual(self.client.ready()["status"], "ok")
        self.assertEqual(self.only()["path"], "/readyz")


if __name__ == "__main__":
    unittest.main()
