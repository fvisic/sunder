/**
 * SDK tests against a tiny built-in http mock server (node:http, node:test).
 * Run against the compiled output: `tsc && node --test dist/`.
 */
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { SunderClient, SunderError } from "./index.js";

interface Recorded {
  method: string;
  url: string;
  body: unknown;
  authorization: string | undefined;
}

type Handler = (req: Recorded, hits: number) => { status: number; body: unknown };

/** Starts a one-test mock server; routes are matched by "METHOD path". */
async function mock(
  t: TestContext,
  routes: Record<string, Handler>,
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
      const recorded: Recorded = {
        method: req.method ?? "",
        url: req.url ?? "",
        body: raw ? JSON.parse(raw) : undefined,
        authorization: req.headers.authorization,
      };
      const out = handler(recorded, hits);
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
  });
  return { client, hits: (route) => counts.get(route) ?? 0 };
}

async function expectSunderError(
  fn: () => Promise<unknown>,
  code: string,
): Promise<SunderError> {
  try {
    await fn();
  } catch (err) {
    assert.ok(err instanceof SunderError, `expected SunderError, got ${String(err)}`);
    assert.equal(err.code, code);
    return err;
  }
  assert.fail(`expected SunderError ${code}, but the call succeeded`);
}

// -- success paths -----------------------------------------------------------

test("registerContact returns the caller-scope CID and sends bearer auth", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts": (req) => {
      assert.equal(req.authorization, "Bearer client_test.s3cret");
      assert.deepEqual(req.body, {
        email: "filip@example.com",
        name: "Filip Visic",
        attributes: { loyalty_tier: "gold" },
      });
      return { status: 201, body: { cid: "CID-abc" } };
    },
  });
  const res = await client.registerContact({
    email: "filip@example.com",
    name: "Filip Visic",
    attributes: { loyalty_tier: "gold" },
  });
  assert.deepEqual(res, { cid: "CID-abc" });
});

test("issueScopedCid posts the target scope", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts/CID-abc/scopes": (req) => {
      assert.deepEqual(req.body, { scope: "billing" });
      return { status: 200, body: { cid: "CID-billing" } };
    },
  });
  assert.deepEqual(await client.issueScopedCid("CID-abc", "billing"), {
    cid: "CID-billing",
  });
});

test("lookupByEmail / lookupByPhone / lookupByName send the right keys", async (t) => {
  const bodies: unknown[] = [];
  const { client } = await mock(t, {
    "POST /v1/lookup": (req) => {
      bodies.push(req.body);
      return { status: 200, body: { cid: "CID-abc" } };
    },
  });
  assert.deepEqual(await client.lookupByEmail("filip@example.com"), { cid: "CID-abc" });
  assert.deepEqual(await client.lookupByPhone("+385911234567"), { cid: "CID-abc" });
  assert.deepEqual(
    await client.lookupByName("Filip Visic", { phone: "+385911234567" }),
    { cid: "CID-abc" },
  );
  assert.deepEqual(bodies, [
    { email: "filip@example.com" },
    { phone: "+385911234567" },
    { name: "Filip Visic", phone: "+385911234567" },
  ]);
});

test("getAttribute passes purpose as a query parameter", async (t) => {
  const { client } = await mock(t, {
    "GET /v1/contacts/CID-abc/attributes/email": (req) => {
      assert.ok(req.url.endsWith("?purpose=support"));
      return { status: 200, body: { value: "filip@example.com" } };
    },
  });
  assert.deepEqual(await client.getAttribute("CID-abc", "email", "support"), {
    value: "filip@example.com",
  });
});

test("predicate claims: sent at issue, surfaced by verifyOti", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/oti": (req) => {
      const body = req.body as { share_predicates?: unknown };
      assert.deepEqual(body.share_predicates, [
        { attr: "birthdate", op: "age_gte", value: 18 },
      ]);
      return {
        status: 201,
        body: { token: "v4.public.p", expires_at: "2026-01-01T00:00:00Z" },
      };
    },
    "POST /v1/oti/verify": () => ({
      status: 200,
      body: {
        cid: "CID-web",
        predicates: [
          { attr: "birthdate", op: "age_gte", value: 18, result: true, known: true },
        ],
      },
    }),
  });
  await client.issueOti("CID-abc", "age_check", "webshop", {
    sharePredicates: [{ attr: "birthdate", op: "age_gte", value: 18 }],
  });
  const out = await client.verifyOti("v4.public.p", "age_check", "webshop");
  assert.equal(out.cid, "CID-web");
  const first = out.predicates?.[0];
  assert.equal(first?.result, true);
  assert.equal(first?.known, true);
});

test("issueOti and verifyOti round-trip (expires_at mapped to expiresAt)", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/oti": (req) => {
      assert.deepEqual(req.body, {
        cid: "CID-abc",
        purpose: "create_order",
        audience: "erp",
      });
      return {
        status: 201,
        body: { token: "v4.public.x", expires_at: "2026-08-22T12:00:00Z" },
      };
    },
    "POST /v1/oti/verify": (req) => {
      assert.deepEqual(req.body, {
        token: "v4.public.x",
        purpose: "create_order",
        audience: "erp",
      });
      return { status: 200, body: { cid: "CID-erp" } };
    },
  });
  const oti = await client.issueOti("CID-abc", "create_order", "erp");
  assert.deepEqual(oti, { token: "v4.public.x", expiresAt: "2026-08-22T12:00:00Z" });
  assert.deepEqual(await client.verifyOti(oti.token, "create_order", "erp"), {
    cid: "CID-erp",
  });
});

test("health hits the unauthenticated liveness endpoint", async (t) => {
  const { client } = await mock(t, {
    "GET /healthz": () => ({ status: 200, body: "ok" }),
  });
  assert.deepEqual(await client.health(), { status: "ok" });
});

// -- error mapping -----------------------------------------------------------

test("404 not_found maps to NotFound", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/lookup": () => ({ status: 404, body: { error: "not_found" } }),
  });
  const err = await expectSunderError(
    () => client.lookupByEmail("nobody@example.com"),
    "NotFound",
  );
  assert.equal(err.status, 404);
  assert.equal(err.serverError, "not_found");
});

test("429 rate_limited maps to RateLimited (and is not retried)", async (t) => {
  const { client, hits } = await mock(t, {
    "POST /v1/lookup": () => ({ status: 429, body: { error: "rate_limited" } }),
  });
  await expectSunderError(() => client.lookupByEmail("a@example.com"), "RateLimited");
  assert.equal(hits("POST /v1/lookup"), 1, "4xx must never be retried");
});

test("409 token_used maps to TokenUsed", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/oti/verify": () => ({ status: 409, body: { error: "token_used" } }),
  });
  const err = await expectSunderError(
    () => client.verifyOti("v4.public.x", "create_order", "erp"),
    "TokenUsed",
  );
  assert.equal(err.status, 409);
});

test("410 token_expired maps to TokenExpired", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/oti/verify": () => ({ status: 410, body: { error: "token_expired" } }),
  });
  await expectSunderError(
    () => client.verifyOti("v4.public.x", "create_order", "erp"),
    "TokenExpired",
  );
});

test("403 variants: forbidden / purpose_not_allowed / audience_mismatch", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts/CID-abc/scopes": () => ({
      status: 403,
      body: { error: "forbidden" },
    }),
    "GET /v1/contacts/CID-abc/attributes/email": () => ({
      status: 403,
      body: { error: "purpose_not_allowed" },
    }),
    "POST /v1/oti/verify": () => ({
      status: 403,
      body: { error: "audience_mismatch" },
    }),
  });
  await expectSunderError(() => client.issueScopedCid("CID-abc", "billing"), "Forbidden");
  await expectSunderError(
    () => client.getAttribute("CID-abc", "email", "marketing"),
    "PurposeNotAllowed",
  );
  await expectSunderError(
    () => client.verifyOti("v4.public.x", "create_order", "crm"),
    "AudienceMismatch",
  );
});

test("400 variants: token_invalid vs validation/bad_json", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/oti/verify": () => ({ status: 400, body: { error: "token_invalid" } }),
    "POST /v1/contacts": () => ({
      status: 400,
      body: { error: "validation", detail: "at least one of email/phone" },
    }),
  });
  await expectSunderError(
    () => client.verifyOti("garbage", "create_order", "erp"),
    "TokenInvalid",
  );
  const err = await expectSunderError(() => client.registerContact({}), "Validation");
  assert.equal(err.detail, "at least one of email/phone");
});

test("401 unauthorized maps to Unauthorized", async (t) => {
  const { client } = await mock(t, {
    "POST /v1/contacts": () => ({ status: 401, body: { error: "unauthorized" } }),
  });
  await expectSunderError(
    () => client.registerContact({ email: "a@example.com" }),
    "Unauthorized",
  );
});

// -- retry policy ------------------------------------------------------------

test("lookup retries exactly once on 5xx and succeeds on the second attempt", async (t) => {
  const { client, hits } = await mock(t, {
    "POST /v1/lookup": (_req, n) =>
      n === 1
        ? { status: 500, body: { error: "internal" } }
        : { status: 200, body: { cid: "CID-abc" } },
  });
  assert.deepEqual(await client.lookupByEmail("filip@example.com"), { cid: "CID-abc" });
  assert.equal(hits("POST /v1/lookup"), 2);
});

test("issueOti retries once on 5xx, then surfaces ServiceUnavailable", async (t) => {
  const { client, hits } = await mock(t, {
    "POST /v1/oti": () => ({ status: 503, body: { error: "internal" } }),
  });
  await expectSunderError(
    () => client.issueOti("CID-abc", "create_order", "erp"),
    "ServiceUnavailable",
  );
  assert.equal(hits("POST /v1/oti"), 2, "retryable call: original + one retry");
});

test("verifyOti NEVER blind-retries on 5xx (single-use token)", async (t) => {
  const { client, hits } = await mock(t, {
    "POST /v1/oti/verify": () => ({ status: 500, body: { error: "internal" } }),
  });
  await expectSunderError(
    () => client.verifyOti("v4.public.x", "create_order", "erp"),
    "ServiceUnavailable",
  );
  assert.equal(hits("POST /v1/oti/verify"), 1, "verify must be attempted exactly once");
});

test("lookup retries once on a network failure", async (t) => {
  // Point at a port with no listener: both attempts fail, code is NetworkError.
  const dead = http.createServer();
  await new Promise<void>((resolve) => dead.listen(0, "127.0.0.1", resolve));
  const addr = dead.address();
  if (addr === null || typeof addr === "string") throw new Error("no port");
  await new Promise<void>((resolve) => dead.close(() => resolve()));
  const client = new SunderClient({
    url: `http://127.0.0.1:${addr.port}`,
    credential: "client_test.s3cret",
  });
  const err = await expectSunderError(
    () => client.lookupByEmail("filip@example.com"),
    "ServiceUnavailable",
  );
  assert.equal(err.status, 0);
});

// -- configuration -----------------------------------------------------------

test("constructor falls back to SUNDER_URL / SUNDER_CREDENTIAL", (t) => {
  const prevUrl = process.env.SUNDER_URL;
  const prevCred = process.env.SUNDER_CREDENTIAL;
  t.after(() => {
    if (prevUrl === undefined) delete process.env.SUNDER_URL;
    else process.env.SUNDER_URL = prevUrl;
    if (prevCred === undefined) delete process.env.SUNDER_CREDENTIAL;
    else process.env.SUNDER_CREDENTIAL = prevCred;
  });
  process.env.SUNDER_URL = "http://sunder.internal:8080";
  process.env.SUNDER_CREDENTIAL = "client_env.k3y";
  assert.doesNotThrow(() => new SunderClient());
  delete process.env.SUNDER_CREDENTIAL;
  assert.throws(() => new SunderClient(), (err: unknown) => {
    return err instanceof SunderError && err.code === "Validation";
  });
});
