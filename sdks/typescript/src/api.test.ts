/**
 * The routes beyond the core handoff surface: consent, data-subject rights,
 * value tokenization, the file vault, shares, links, version history,
 * external claims and the admin unlock.
 *
 * Each test asserts the wire contract and the properties a client can get
 * wrong: an empty cascade must not be sent as an opt-in, bulk routes must
 * carry the unlock token, and destructive calls are never blind-retried.
 */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { SunderClient, SunderError, type SunderClientOptions } from "./index.js";

interface Recorded {
  method: string;
  url: string;
  body: unknown;
  raw: string;
  headers: http.IncomingHttpHeaders;
}

type Handler = (req: Recorded, hits: number) => { status: number; body: unknown };

async function mock(
  t: TestContext,
  routes: Record<string, Handler>,
  clientOptions: Partial<SunderClientOptions> = {},
): Promise<{ client: SunderClient; hits: (route: string) => number }> {
  const counts = new Map<string, number>();
  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const path = (req.url ?? "").split("?")[0];
      const key = `${req.method} ${path}`;
      const handler = routes[key];
      if (!handler) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal", detail: `no mock for ${key}` }));
        return;
      }
      const hits = (counts.get(key) ?? 0) + 1;
      counts.set(key, hits);
      let parsed: unknown;
      try {
        parsed = raw ? JSON.parse(raw) : undefined;
      } catch {
        parsed = undefined; // multipart, not JSON
      }
      const out = handler(
        { method: req.method ?? "", url: req.url ?? "", body: parsed, raw, headers: req.headers },
        hits,
      );
      if (typeof out.body === "string") {
        res.writeHead(out.status, { "Content-Type": "text/plain" });
        res.end(out.body);
      } else {
        res.writeHead(out.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(out.body));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  const client = new SunderClient({
    url: `http://127.0.0.1:${addr.port}`,
    credential: "client_test.s3cret",
    ...clientOptions,
  });
  return { client, hits: (route) => counts.get(route) ?? 0 };
}

async function expectSunderError(fn: () => Promise<unknown>, code: string): Promise<void> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof SunderError, `expected SunderError, got ${String(err)}`);
    assert.equal(err.code, code);
    return;
  }
  assert.fail(`expected SunderError ${code}, but the call succeeded`);
}

// -- consent -----------------------------------------------------------------

test("setConsent sends a real boolean and getConsent decodes the list", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/consent": (req) => {
      assert.deepEqual(req.body, { cid: "CID1", purpose: "billing", granted: false });
      return { status: 200, body: { cid: "CID1", purpose: "billing", granted: false } };
    },
    "GET /v1/consent/CID1": () => ({
      status: 200,
      body: { consents: [{ purpose: "billing", granted: true, updated_at: "2026-01-01T00:00:00Z" }] },
    }),
  });
  const set = await client.setConsent("CID1", "billing", false);
  assert.equal(set.granted, false);
  const list = await client.getConsent("CID1");
  assert.equal(list.length, 1);
  assert.equal(list[0]!.granted, true);
});

// -- data subject rights -----------------------------------------------------

test("dsrAccess carries the holdings that do not live in the blob", async (t) => {
  const { client } = await mock(t, {
    "GET /v1/dsr/access": (req) => {
      assert.ok(req.url.includes("cid=CID1"));
      return {
        status: 200,
        body: {
          scopes: [
            {
              scope: "crm",
              cid: "CID1",
              attributes: { email: "a@b.c" },
              value_tokens: [{ token: "tok_1", type: "card" }],
              files: [{ id: "f1", name: "scan.pdf" }],
              shares: [{ uuid: "u1", partner_label: "partner-bank", fields: ["email"] }],
              links: [{ cid: "CID2", link_type: "guardian", role: "parent" }],
            },
          ],
          audit_trail: [
            { ts: "2026-01-01T00:00:00Z", client_id: "crm", user_id: "agent-7", action: "lookup", count: 3 },
          ],
        },
      };
    },
  });
  const res = await client.dsrAccess("CID1");
  const scope = res.scopes[0]!;
  assert.equal(scope.value_tokens?.length, 1);
  assert.equal(scope.files?.length, 1);
  // The share's recipient label IS the Article 15 answer.
  assert.equal(scope.shares?.[0]?.partner_label, "partner-bank");
  assert.equal(scope.links?.length, 1);
  assert.equal(res.audit_trail?.[0]?.count, 3);
});

test("dsrExport is caller-scope only", async (t) => {
  const { client } = await mock(t, {
    "GET /v1/dsr/export": (req) => {
      assert.ok(req.url.includes("cid=CID1"));
      return { status: 200, body: { scope: "crm", cid: "CID1", attributes: { email: "a@b.c" } } };
    },
  });
  const res = await client.dsrExport("CID1");
  assert.equal(res.scope, "crm");
  assert.equal(res.attributes?.email, "a@b.c");
});

test("dsrErase omits cascade entirely when none was requested", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/dsr/erase": (req) => {
      assert.deepEqual(req.body, { cid: "CID1" });
      return {
        status: 200,
        body: { erasure_id: 7, scopes: 2, linked: [{ cid: "CID2", link_type: "guardian", cascaded: false }] },
      };
    },
  });
  const res = await client.dsrErase("CID1");
  assert.equal(res.erasure_id, 7);
  assert.equal(res.linked?.[0]?.cascaded, false);
});

test("dsrErase forwards named link types and never sends an empty list", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/dsr/erase": (req) => {
      const body = req.body as Record<string, unknown>;
      assert.deepEqual(body["cascade"], ["guardian"]);
      return { status: 200, body: { erasure_id: 8, scopes: 1 } };
    },
  });
  await client.dsrErase("CID1", ["guardian"]);

  const empty = await mock(t, {
    "POST /v1/dsr/erase": (req) => {
      assert.ok(!("cascade" in (req.body as Record<string, unknown>)));
      return { status: 200, body: { erasure_id: 9, scopes: 1 } };
    },
  });
  await empty.client.dsrErase("CID1", []);
});

test("dsrErase is never retried - it is destructive", async (t) => {
  const { client, hits } = await mock(t, {
    "POST /v1/dsr/erase": () => ({ status: 503, body: { error: "service_unavailable" } }),
  });
  await expectSunderError(() => client.dsrErase("CID1"), "ServiceUnavailable");
  assert.equal(hits("POST /v1/dsr/erase"), 1);
});

// -- value tokenization ------------------------------------------------------

test("tokenize omits an unset cid and detokenize round-trips", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/tokens": (req) => {
      const body = req.body as Record<string, unknown>;
      assert.equal(body["cid"], undefined);
      assert.equal(body["unique"], true);
      return { status: 201, body: { token: "tok_abc" } };
    },
    "GET /v1/tokens/tok_abc": () => ({ status: 200, body: { value: "4111111111111111" } }),
  });
  const token = await client.tokenize({ value: "4111111111111111", type: "card", unique: true });
  assert.equal(token, "tok_abc");
  assert.equal(await client.detokenize("tok_abc"), "4111111111111111");
});

test("deleteToken is a DELETE and is not retried", async (t) => {
  const { client, hits } = await mock(t, {
    "DELETE /v1/tokens/tok_1": () => ({ status: 503, body: { error: "service_unavailable" } }),
  });
  await expectSunderError(() => client.deleteToken("tok_1"), "ServiceUnavailable");
  assert.equal(hits("DELETE /v1/tokens/tok_1"), 1);
});

test("bulk routes always carry the unlock token and are not retried", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/tokens/bulk": (req) => {
      assert.equal(req.headers["x-sunder-unlock"], "unlock_xyz");
      return { status: 201, body: { tokens: ["t1", "t2"] } };
    },
  });
  const tokens = await client.tokenizeBulk("unlock_xyz", [{ value: "a" }, { value: "b" }]);
  assert.deepEqual(tokens, ["t1", "t2"]);

  // Spent by the first attempt: a retry would come back already-used.
  const failing = await mock(t, {
    "POST /v1/tokens/bulk/read": () => ({ status: 503, body: { error: "service_unavailable" } }),
  });
  await expectSunderError(
    () => failing.client.detokenizeBulk("unlock_xyz", ["t1"]),
    "ServiceUnavailable",
  );
  assert.equal(failing.hits("POST /v1/tokens/bulk/read"), 1);
});

// -- file vault --------------------------------------------------------------

test("uploadFile sends multipart with the filename and the expiry header", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts/CID1/files": (req) => {
      assert.ok(String(req.headers["content-type"]).startsWith("multipart/form-data"));
      assert.ok(req.raw.includes('filename="scan.pdf"'));
      assert.ok(req.raw.includes("hello"));
      assert.equal(req.headers["x-sunder-file-expiry"], "2030-01-02T03:04:05Z");
      return { status: 201, body: { id: "f1", name: "scan.pdf", sha256: "deadbeef" } };
    },
  });
  const meta = await client.uploadFile(
    "CID1",
    new Blob(["hello"], { type: "application/pdf" }),
    "scan.pdf",
    "2030-01-02T03:04:05Z",
  );
  assert.equal(meta.sha256, "deadbeef");
});

test("uploadFile omits the expiry header when no deadline is given", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts/CID1/files": (req) => {
      assert.equal(req.headers["x-sunder-file-expiry"], undefined);
      return { status: 201, body: { id: "f1" } };
    },
  });
  await client.uploadFile("CID1", new Blob(["x"]), "a.txt");
});

test("listFiles sends the purpose and downloadFile maps errors instead of returning a body", async (t) => {
  const { client } = await mock(t, {
    "GET /v1/contacts/CID1/files": (req) => {
      assert.ok(req.url.includes("purpose=support"));
      return { status: 200, body: { files: [{ id: "f1", name: "scan.pdf" }] } };
    },
    "GET /v1/files/f1": () => ({ status: 200, body: "raw-bytes" }),
    "GET /v1/files/missing": () => ({ status: 404, body: { error: "not_found" } }),
  });
  const files = await client.listFiles("CID1", "support");
  assert.equal(files[0]!.id, "f1");
  const blob = await client.downloadFile("f1", "support");
  assert.equal(await blob.text(), "raw-bytes");
  await expectSunderError(() => client.downloadFile("missing", "support"), "NotFound");
});

// -- shares, links, versions --------------------------------------------------

test("createShare sends the partner label the Article 15 answer reports", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/shares": (req) => {
      const body = req.body as Record<string, unknown>;
      assert.equal(body["partner_label"], "partner-bank");
      assert.deepEqual(body["fields"], ["email"]);
      return { status: 201, body: { uuid: "u1", expires_at: "2026-01-01T00:00:00Z" } };
    },
    "GET /v1/shares/u1": () => ({ status: 200, body: { fields: { email: "a@b.c" } } }),
    "DELETE /v1/shares/u1": () => ({ status: 200, body: { status: "revoked" } }),
  });
  const share = await client.createShare({
    cid: "CID1",
    fields: ["email"],
    partner_label: "partner-bank",
    purpose: "kyc",
    ttl_seconds: 3600,
  });
  assert.equal(share.uuid, "u1");
  assert.deepEqual(await client.fetchShare("u1"), { email: "a@b.c" });
  await client.revokeShare("u1");
});

test("links round-trip and report the role this cid plays", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/links": (req) => {
      assert.deepEqual(req.body, {
        parent_cid: "PARENT",
        child_cid: "CHILD",
        link_type: "guardian",
      });
      return { status: 201, body: { status: "linked" } };
    },
    "GET /v1/contacts/PARENT/links": () => ({
      status: 200,
      body: { links: [{ cid: "CHILD", link_type: "guardian", role: "parent" }] },
    }),
    "DELETE /v1/links": (req) => {
      assert.deepEqual(req.body, { parent_cid: "PARENT", child_cid: "CHILD" });
      return { status: 200, body: { status: "unlinked" } };
    },
  });
  await client.link("PARENT", "CHILD", "guardian");
  const links = await client.listLinks("PARENT");
  assert.equal(links[0]!.role, "parent");
  await client.unlink("PARENT", "CHILD");
});

test("a historical attribute read still sends the purpose", async (t) => {
  const { client } = await mock(t, {
    "GET /v1/contacts/CID1/versions": () => ({
      status: 200,
      body: { versions: [{ version_no: 2, written_by: "crm" }] },
    }),
    "GET /v1/contacts/CID1/versions/2/attributes/email": (req) => {
      // An old value is not a lesser secret.
      assert.ok(req.url.includes("purpose=support"));
      return { status: 200, body: { value: "old@example.com" } };
    },
  });
  const versions = await client.listVersions("CID1");
  assert.equal(versions[0]!.version_no, 2);
  assert.equal(await client.getVersionAttribute("CID1", 2, "email", "support"), "old@example.com");
});

// -- claims, unlock, attribution ---------------------------------------------

test("storeExternalClaim forwards the envelope and returns the stored names", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/claims/external": (req) => {
      const body = req.body as Record<string, unknown>;
      assert.equal(body["envelope"], "eyJ...envelope");
      return { status: 200, body: { stored: ["verified_age@gov-id"] } };
    },
  });
  const stored = await client.storeExternalClaim("CID1", "eyJ...envelope");
  assert.ok(stored[0]!.includes("@"), "issuer provenance must survive in the name");
});

test("unlock mints a single-use token for one purpose", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/admin/unlock": (req) => {
      assert.deepEqual(req.body, { purpose: "tokens" });
      return { status: 201, body: { unlock_token: "unlock_xyz", expires_at: "2026-01-01T00:01:00Z" } };
    },
  });
  const unlock = await client.unlock("tokens");
  assert.equal(unlock.unlock_token, "unlock_xyz");
});

test("userId is sent on every call as X-Sunder-User-Id", async (t) => {
  const { client } = await mock(
    t,
    {
      "GET /v1/contacts/CID1/attributes/email": (req) => {
        assert.equal(req.headers["x-sunder-user-id"], "agent-7");
        return { status: 200, body: { value: "a@b.c" } };
      },
    },
    { userId: "agent-7" },
  );
  await client.getAttribute("CID1", "email", "support");
});

test("ready reports the readiness probe, not liveness", async (t) => {
  const { client } = await mock(t, {
    "GET /readyz": () => ({ status: 200, body: "ok" }),
  });
  assert.equal((await client.ready()).status, "ok");
});
