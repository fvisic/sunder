"""Tests for the Sunder Python SDK against a threaded stdlib mock server."""

import http.server
import json
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import sunder_client


class MockHandler(http.server.BaseHTTPRequestHandler):
    """Replays queued responses and records every request it serves."""

    server_version = "SunderMock/0"

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.requests.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": json.loads(body) if body else None,
        })
        if self.server.responses:
            status, payload = self.server.responses.pop(0)
        else:
            status, payload = 500, {"error": "internal"}
        if isinstance(payload, dict | list):
            data = json.dumps(payload).encode("utf-8")
            ctype = "application/json"
        else:
            data = str(payload).encode("utf-8")
            ctype = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _serve

    def log_message(self, *args):  # keep test output clean
        pass


class ClientTest(unittest.TestCase):
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

    # -- success paths -----------------------------------------------------

    def test_register_contact(self):
        self.queue((201, {"cid": "CID-1"}))
        cid = self.client.register_contact({"email": "a@b.c", "name": "A B"})
        self.assertEqual(cid, "CID-1")
        req = self.server.requests[0]
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["path"], "/v1/contacts")
        self.assertEqual(req["body"], {"email": "a@b.c", "name": "A B"})
        self.assertEqual(req["headers"]["Authorization"], "Bearer client_id.secret")
        self.assertEqual(req["headers"]["Content-Type"], "application/json")

    def test_issue_scoped_cid(self):
        self.queue((200, {"cid": "CID-billing"}))
        cid = self.client.issue_scoped_cid("CID-1", "billing")
        self.assertEqual(cid, "CID-billing")
        req = self.server.requests[0]
        self.assertEqual(req["path"], "/v1/contacts/CID-1/scopes")
        self.assertEqual(req["body"], {"scope": "billing"})

    def test_lookup_by_email(self):
        self.queue((200, {"cid": "CID-1"}))
        self.assertEqual(self.client.lookup_by_email("a@b.c"), "CID-1")
        self.assertEqual(self.server.requests[0]["body"], {"email": "a@b.c"})
        self.assertEqual(self.server.requests[0]["path"], "/v1/lookup")

    def test_lookup_by_phone(self):
        self.queue((200, {"cid": "CID-1"}))
        self.assertEqual(self.client.lookup_by_phone("+385911234567"), "CID-1")
        self.assertEqual(self.server.requests[0]["body"], {"phone": "+385911234567"})

    def test_lookup_by_name_with_email(self):
        self.queue((200, {"cid": "CID-1"}))
        self.assertEqual(self.client.lookup_by_name("A B", email="a@b.c"), "CID-1")
        self.assertEqual(self.server.requests[0]["body"],
                         {"name": "A B", "email": "a@b.c"})

    def test_lookup_by_name_requires_second_factor(self):
        with self.assertRaises(sunder_client.ValidationError):
            self.client.lookup_by_name("A B")
        self.assertEqual(self.server.requests, [])

    def test_get_attribute(self):
        self.queue((200, {"value": "gold"}))
        val = self.client.get_attribute("CID-1", "loyalty_tier", "support")
        self.assertEqual(val, "gold")
        self.assertEqual(self.server.requests[0]["method"], "GET")
        self.assertEqual(self.server.requests[0]["path"],
                         "/v1/contacts/CID-1/attributes/loyalty_tier?purpose=support")

    def test_issue_oti(self):
        self.queue((201, {"token": "v4.public.x",
                          "expires_at": "2026-01-01T00:00:00Z"}))
        out = self.client.issue_oti("CID-1", "create_order", "erp")
        self.assertEqual(out, {"token": "v4.public.x",
                               "expires_at": "2026-01-01T00:00:00Z"})
        self.assertEqual(self.server.requests[0]["body"],
                         {"cid": "CID-1", "purpose": "create_order", "audience": "erp"})

    def test_verify_oti(self):
        self.queue((200, {"cid": "CID-erp"}))
        cid = self.client.verify_oti("v4.public.x", "create_order", "erp")
        self.assertEqual(cid, "CID-erp")
        self.assertEqual(self.server.requests[0]["path"], "/v1/oti/verify")

    def test_predicates_roundtrip(self):
        self.queue((201, {"token": "v4.public.x",
                          "expires_at": "2026-01-01T00:00:00Z"}))
        self.client.issue_oti("CID-1", "age_check", "webshop",
                              share_predicates=[{"attr": "birthdate",
                                                 "op": "age_gte", "value": 18}])
        self.assertEqual(self.server.requests[0]["body"]["share_predicates"],
                         [{"attr": "birthdate", "op": "age_gte", "value": 18}])

        self.server.requests.clear()
        self.queue((200, {"cid": "CID-web",
                          "predicates": [{"attr": "birthdate", "op": "age_gte",
                                          "value": 18, "result": True,
                                          "known": True}]}))
        out = self.client.verify_oti_full("v4.public.x", "age_check", "webshop")
        self.assertEqual(out["cid"], "CID-web")
        self.assertTrue(out["predicates"][0]["result"])
        self.assertTrue(out["predicates"][0]["known"])

    def test_health(self):
        self.queue((200, "ok"))
        self.assertEqual(self.client.health(), {"status": "ok"})
        self.assertEqual(self.server.requests[0]["path"], "/healthz")

    # -- error mapping -------------------------------------------------------

    def _assert_error(self, status, code, exc_type):
        self.server.requests.clear()
        self.server.responses.clear()
        self.queue((status, {"error": code}))
        with self.assertRaises(exc_type) as ctx:
            self.client.verify_oti("t", "p", "a")
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(ctx.exception.status, status)

    def test_error_mapping(self):
        cases = [
            (401, "unauthorized", sunder_client.UnauthorizedError),
            (403, "forbidden", sunder_client.ForbiddenError),
            (403, "purpose_not_allowed", sunder_client.PurposeNotAllowedError),
            (403, "audience_mismatch", sunder_client.AudienceMismatchError),
            (404, "not_found", sunder_client.NotFoundError),
            (400, "validation", sunder_client.ValidationError),
            (400, "bad_json", sunder_client.ValidationError),
            (400, "token_invalid", sunder_client.TokenInvalidError),
            (409, "token_used", sunder_client.TokenUsedError),
            (410, "token_expired", sunder_client.TokenExpiredError),
            (429, "rate_limited", sunder_client.RateLimitedError),
            (500, "internal", sunder_client.ServiceUnavailableError),
        ]
        for status, code, exc_type in cases:
            with self.subTest(code=code):
                self._assert_error(status, code, exc_type)

    def test_errors_are_sunder_errors(self):
        self.queue((404, {"error": "not_found"}))
        with self.assertRaises(sunder_client.SunderError):
            self.client.lookup_by_email("a@b.c")

    def test_validation_detail_preserved(self):
        self.queue((400, {"error": "validation", "detail": "name alone is rejected"}))
        with self.assertRaises(sunder_client.ValidationError) as ctx:
            self.client.lookup_by_name("A B", email="x@y.z")
        self.assertEqual(ctx.exception.detail, "name alone is rejected")

    # -- retry policy -------------------------------------------------------

    def test_lookup_retries_once_on_5xx(self):
        self.queue((500, {"error": "internal"}), (200, {"cid": "CID-1"}))
        self.assertEqual(self.client.lookup_by_email("a@b.c"), "CID-1")
        self.assertEqual(len(self.server.requests), 2)

    def test_issue_oti_retries_once_then_gives_up(self):
        self.queue((503, {"error": "internal"}), (503, {"error": "internal"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.issue_oti("CID-1", "p", "erp")
        self.assertEqual(len(self.server.requests), 2)

    def test_verify_oti_never_retries_on_5xx(self):
        self.queue((500, {"error": "internal"}), (200, {"cid": "CID-erp"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.verify_oti("t", "p", "erp")
        self.assertEqual(len(self.server.requests), 1)

    def test_register_does_not_retry_on_5xx(self):
        self.queue((500, {"error": "internal"}), (201, {"cid": "CID-1"}))
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            self.client.register_contact({"email": "a@b.c"})
        self.assertEqual(len(self.server.requests), 1)

    def test_lookup_no_retry_on_4xx(self):
        self.queue((404, {"error": "not_found"}), (200, {"cid": "CID-1"}))
        with self.assertRaises(sunder_client.NotFoundError):
            self.client.lookup_by_email("a@b.c")
        self.assertEqual(len(self.server.requests), 1)

    def test_lookup_retries_on_network_error(self):
        # Point at a closed port: connection refused both times -> gives up.
        dead = sunder_client.SunderClient(url="http://127.0.0.1:1",
                                          credential="c.s", timeout=1)
        with self.assertRaises(sunder_client.ServiceUnavailableError) as ctx:
            dead.lookup_by_email("a@b.c")
        self.assertEqual(ctx.exception.code, "service_unavailable")

    def test_verify_network_error_maps_without_retry(self):
        dead = sunder_client.SunderClient(url="http://127.0.0.1:1",
                                          credential="c.s", timeout=1)
        with self.assertRaises(sunder_client.ServiceUnavailableError):
            dead.verify_oti("t", "p", "a")

    # -- config -------------------------------------------------------------

    def test_env_config(self):
        os.environ["SUNDER_URL"] = self.url
        os.environ["SUNDER_CREDENTIAL"] = "env_client.env_secret"
        try:
            c = sunder_client.SunderClient()
            self.queue((200, {"cid": "CID-1"}))
            c.lookup_by_email("a@b.c")
            self.assertEqual(self.server.requests[0]["headers"]["Authorization"],
                             "Bearer env_client.env_secret")
        finally:
            del os.environ["SUNDER_URL"]
            del os.environ["SUNDER_CREDENTIAL"]

    def test_missing_config_raises(self):
        os.environ.pop("SUNDER_URL", None)
        os.environ.pop("SUNDER_CREDENTIAL", None)
        with self.assertRaises(ValueError):
            sunder_client.SunderClient()


if __name__ == "__main__":
    unittest.main()
