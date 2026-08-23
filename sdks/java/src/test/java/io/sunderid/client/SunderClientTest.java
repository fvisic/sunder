package io.sunderid.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test suite for the Sunder Java SDK. Plain Java (no JUnit, no dependencies):
 * a main-method runner with asserts against a com.sun.net.httpserver mock.
 *
 * Run: bash run-tests.sh (or java io.sunderid.client.SunderClientTest with
 * both class output directories on the classpath).
 */
public final class SunderClientTest {

    // -- tiny test framework ---------------------------------------------------

    private static int passed = 0;
    private static final List<String> failures = new ArrayList<>();

    private static void run(String name, Runnable test) {
        try {
            mock.reset();
            test.run();
            passed++;
            System.out.println("PASS " + name);
        } catch (Throwable t) {
            failures.add(name + ": " + t);
            System.out.println("FAIL " + name + ": " + t);
            t.printStackTrace(System.out);
        }
    }

    private static void assertEquals(Object expected, Object actual, String what) {
        if (!Objects.equals(expected, actual)) {
            throw new AssertionError(what + ": expected <" + expected + "> but was <" + actual + ">");
        }
    }

    private static void assertTrue(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError(what);
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> T expectThrows(Class<T> type, Runnable body) {
        try {
            body.run();
        } catch (Throwable t) {
            if (t.getClass() == type) {
                return (T) t;
            }
            throw new AssertionError("expected exactly " + type.getSimpleName()
                    + " but got " + t.getClass().getSimpleName() + ": " + t, t);
        }
        throw new AssertionError("expected " + type.getSimpleName() + " but nothing was thrown");
    }

    // -- mock server -------------------------------------------------------------

    /** One recorded inbound request. */
    private record Recorded(String method, String path, String query,
                            String authorization, String contentType, String accept,
                            String body) {
    }

    /** One scripted response. */
    private record Scripted(int status, String body, long delayMs) {
    }

    private static final class MockServer {
        final HttpServer server;
        final List<Recorded> requests = new CopyOnWriteArrayList<>();
        final Deque<Scripted> responses = new ArrayDeque<>();

        MockServer() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            // Concurrent executor: with the default (calling-thread) executor a
            // deliberately slow handler would serialize and starve retry attempts.
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        synchronized void enqueue(int status, String body) {
            responses.add(new Scripted(status, body, 0));
        }

        synchronized void enqueueSlow(int status, String body, long delayMs) {
            responses.add(new Scripted(status, body, delayMs));
        }

        synchronized void reset() {
            requests.clear();
            responses.clear();
        }

        private void handle(HttpExchange exchange) throws java.io.IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            requests.add(new Recorded(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestURI().getRawQuery(),
                    exchange.getRequestHeaders().getFirst("Authorization"),
                    exchange.getRequestHeaders().getFirst("Content-Type"),
                    exchange.getRequestHeaders().getFirst("Accept"),
                    body));
            Scripted scripted;
            synchronized (this) {
                scripted = responses.poll();
            }
            if (scripted == null) {
                scripted = new Scripted(200, "{\"cid\":\"CID-default\"}", 0);
            }
            if (scripted.delayMs() > 0) {
                try {
                    Thread.sleep(scripted.delayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            byte[] out = scripted.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(scripted.status(), out.length == 0 ? -1 : out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
            exchange.close();
        }

        Recorded only() {
            assertEquals(1, requests.size(), "request count");
            return requests.get(0);
        }
    }

    private static MockServer mock;
    private static SunderClient client;

    // -- entry point -------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("env-child")) {
            envChild();
            return;
        }
        if (args.length > 0 && args[0].equals("env-missing-child")) {
            envMissingChild();
            return;
        }

        mock = new MockServer();
        client = new SunderClient(mock.baseUrl(), "test_client.test_secret");

        run("registerContact success", SunderClientTest::testRegisterContact);
        run("issueScopedCid success + path encoding", SunderClientTest::testIssueScopedCid);
        run("lookupByEmail success", SunderClientTest::testLookupByEmail);
        run("lookupByPhone success", SunderClientTest::testLookupByPhone);
        run("lookupByName with second factor", SunderClientTest::testLookupByName);
        run("lookupByName without second factor fails locally", SunderClientTest::testLookupByNameNoFactor);
        run("getAttribute success + query encoding", SunderClientTest::testGetAttribute);
        run("issueOti success", SunderClientTest::testIssueOti);
        run("verifyOti success", SunderClientTest::testVerifyOti);
        run("predicate claims roundtrip", SunderClientTest::testPredicateClaims);
        run("health success (unauthenticated)", SunderClientTest::testHealth);
        run("health empty body defaults to ok", SunderClientTest::testHealthEmptyBody);
        run("health failure maps taxonomy", SunderClientTest::testHealthFailure);
        run("full error mapping (error field first, then status)", SunderClientTest::testErrorMapping);
        run("error mapping without JSON body falls back to status", SunderClientTest::testErrorMappingNoBody);
        run("unknown status maps to base SunderException", SunderClientTest::testUnknownStatus);
        run("lookup retries exactly once on 5xx", SunderClientTest::testLookupRetriesOnce);
        run("issueOti retries exactly once on 5xx", SunderClientTest::testIssueOtiRetriesOnce);
        run("retry stops after the second failure", SunderClientTest::testRetryStopsAfterSecondFailure);
        run("registerContact never retries", SunderClientTest::testRegisterNeverRetries);
        run("issueScopedCid never retries", SunderClientTest::testIssueScopedCidNeverRetries);
        run("getAttribute never retries", SunderClientTest::testGetAttributeNeverRetries);
        run("verifyOti NEVER retries on 5xx", SunderClientTest::testVerifyOtiNeverRetries5xx);
        run("verifyOti NEVER retries on timeout (single attempt)", SunderClientTest::testVerifyOtiNeverRetriesTimeout);
        run("lookup retries once on network-level timeout", SunderClientTest::testLookupRetriesOnTimeout);
        run("network failure maps to ServiceUnavailable (status null)", SunderClientTest::testNetworkFailure);
        run("trailing slashes stripped from base URL", SunderClientTest::testTrailingSlash);
        run("non-JSON success body maps to bad_response", SunderClientTest::testBadResponseBody);
        run("env config via SUNDER_URL / SUNDER_CREDENTIAL", SunderClientTest::testEnvConfig);
        run("missing config rejected", SunderClientTest::testMissingConfig);

        mock.server.stop(0);
        System.out.println();
        System.out.println("SUMMARY: " + passed + " passed, " + failures.size() + " failed, "
                + (passed + failures.size()) + " total");
        if (!failures.isEmpty()) {
            failures.forEach(f -> System.out.println("  FAILED: " + f));
            System.exit(1);
        }
    }

    // -- success paths -------------------------------------------------------------

    private static void testRegisterContact() {
        mock.enqueue(201, "{\"cid\":\"CID-abc\"}");
        String cid = client.registerContact(Map.of(
                "email", "Filip@Example.com",
                "emails", List.of("f2@example.com", "f3@example.com"),
                "name", "Filip Visic",
                "attributes", Map.of("loyalty_tier", "gold")));
        assertEquals("CID-abc", cid, "cid");
        Recorded req = mock.only();
        assertEquals("POST", req.method(), "method");
        assertEquals("/v1/contacts", req.path(), "path");
        assertEquals("Bearer test_client.test_secret", req.authorization(), "Authorization");
        assertEquals("application/json", req.contentType(), "Content-Type");
        assertEquals("application/json", req.accept(), "Accept");
        Map<String, Object> sent = Json.parseObject(req.body());
        assertEquals("Filip@Example.com", sent.get("email"), "body email");
        assertEquals("Filip Visic", sent.get("name"), "body name");
        assertEquals(List.of("f2@example.com", "f3@example.com"), sent.get("emails"), "body emails");
        assertEquals(Map.of("loyalty_tier", "gold"), sent.get("attributes"), "nested attributes");
    }

    private static void testIssueScopedCid() {
        mock.enqueue(200, "{\"cid\":\"CID-billing\"}");
        String cid = client.issueScopedCid("CID a/b", "billing");
        assertEquals("CID-billing", cid, "cid");
        Recorded req = mock.only();
        assertEquals("POST", req.method(), "method");
        // The raw segment must be percent-encoded; HttpExchange decodes the path.
        assertEquals("/v1/contacts/CID a/b/scopes", req.path(), "decoded path");
        assertEquals(Map.of("scope", "billing"), Json.parseObject(req.body()), "body");
    }

    private static void testLookupByEmail() {
        mock.enqueue(200, "{\"cid\":\"CID-e\"}");
        assertEquals("CID-e", client.lookupByEmail("filip@example.com"), "cid");
        Recorded req = mock.only();
        assertEquals("POST", req.method(), "method");
        assertEquals("/v1/lookup", req.path(), "path");
        assertEquals(Map.of("email", "filip@example.com"), Json.parseObject(req.body()), "body");
        assertEquals("Bearer test_client.test_secret", req.authorization(), "Authorization");
    }

    private static void testLookupByPhone() {
        mock.enqueue(200, "{\"cid\":\"CID-p\"}");
        assertEquals("CID-p", client.lookupByPhone("+385 91 123 4567"), "cid");
        Recorded req = mock.only();
        assertEquals("/v1/lookup", req.path(), "path");
        assertEquals(Map.of("phone", "+385 91 123 4567"), Json.parseObject(req.body()), "body");
    }

    private static void testLookupByName() {
        mock.enqueue(200, "{\"cid\":\"CID-n\"}");
        assertEquals("CID-n", client.lookupByName("Filip Visic", "filip@example.com", null), "cid");
        Recorded req = mock.only();
        Map<String, Object> body = Json.parseObject(req.body());
        assertEquals(Map.of("name", "Filip Visic", "email", "filip@example.com"), body, "body");
        assertTrue(!body.containsKey("phone"), "phone must be absent when null");

        mock.reset();
        mock.enqueue(200, "{\"cid\":\"CID-n2\"}");
        assertEquals("CID-n2", client.lookupByName("Filip Visic", null, "+385911234567"), "cid");
        assertEquals(Map.of("name", "Filip Visic", "phone", "+385911234567"),
                Json.parseObject(mock.only().body()), "body with phone");
    }

    private static void testLookupByNameNoFactor() {
        ValidationException e = expectThrows(ValidationException.class,
                () -> client.lookupByName("Filip Visic", null, null));
        assertEquals("validation", e.getCode(), "code");
        assertEquals(null, e.getStatus(), "status");
        assertTrue(e.getDetail().contains("second factor"), "detail mentions second factor");
        assertEquals(0, mock.requests.size(), "no HTTP request must be made");
    }

    private static void testGetAttribute() {
        mock.enqueue(200, "{\"value\":\"gold\"}");
        String value = client.getAttribute("CID-abc", "loyalty tier", "customer support");
        assertEquals("gold", value, "value");
        Recorded req = mock.only();
        assertEquals("GET", req.method(), "method");
        assertEquals("/v1/contacts/CID-abc/attributes/loyalty tier", req.path(), "decoded path");
        assertEquals("purpose=customer%20support", req.query(), "raw query");
        assertEquals("", req.body(), "GET has no body");
        assertEquals(null, req.contentType(), "no Content-Type on GET");
        assertEquals("Bearer test_client.test_secret", req.authorization(), "Authorization");
    }

    private static void testIssueOti() {
        mock.enqueue(201, "{\"token\":\"v4.public.xyz\",\"expires_at\":\"2026-08-22T10:00:00Z\"}");
        OtiResult oti = client.issueOti("CID-abc", "create_order", "erp");
        assertEquals("v4.public.xyz", oti.token(), "token");
        assertEquals("2026-08-22T10:00:00Z", oti.expiresAt(), "expiresAt");
        Recorded req = mock.only();
        assertEquals("POST", req.method(), "method");
        assertEquals("/v1/oti", req.path(), "path");
        assertEquals(Map.of("cid", "CID-abc", "purpose", "create_order", "audience", "erp"),
                Json.parseObject(req.body()), "body");
    }

    private static void testVerifyOti() {
        mock.enqueue(200, "{\"cid\":\"CID-erp\"}");
        assertEquals("CID-erp", client.verifyOti("v4.public.xyz", "create_order", "erp"), "cid");
        Recorded req = mock.only();
        assertEquals("POST", req.method(), "method");
        assertEquals("/v1/oti/verify", req.path(), "path");
        assertEquals(Map.of("token", "v4.public.xyz", "purpose", "create_order", "audience", "erp"),
                Json.parseObject(req.body()), "body");
    }

    private static void testPredicateClaims() {
        mock.enqueue(201, "{\"token\":\"v4.public.p\",\"expires_at\":\"2026-01-01T00:00:00Z\"}");
        client.issueOti("CID-1", "age_check", "webshop", null,
                java.util.List.of(new java.util.LinkedHashMap<>(Map.of(
                        "attr", "birthdate", "op", "age_gte", "value", 18))));
        Recorded issueReq = mock.only();
        Object preds = Json.parseObject(issueReq.body()).get("share_predicates");
        assertEquals(true, preds != null, "share_predicates sent");

        mock.enqueue(200, "{\"cid\":\"CID-web\",\"predicates\":[{\"attr\":\"birthdate\",\"op\":\"age_gte\",\"value\":18,\"result\":true,\"known\":true}]}");
        Map<String, Object> out = client.verifyOtiFull("v4.public.p", "age_check", "webshop");
        assertEquals("CID-web", out.get("cid"), "cid");
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) ((java.util.List<Object>) out.get("predicates")).get(0);
        assertEquals(Boolean.TRUE, first.get("result"), "predicate result");
        assertEquals(Boolean.TRUE, first.get("known"), "predicate known");
    }

    private static void testHealth() {
        mock.enqueue(200, "ok\n");
        assertEquals("ok", client.health(), "status");
        Recorded req = mock.only();
        assertEquals("GET", req.method(), "method");
        assertEquals("/healthz", req.path(), "path");
        assertEquals(null, req.authorization(), "healthz is unauthenticated");
    }

    private static void testHealthEmptyBody() {
        mock.enqueue(200, "");
        assertEquals("ok", client.health(), "status defaults to ok");
    }

    private static void testHealthFailure() {
        mock.enqueue(503, "");
        ServiceUnavailableException e = expectThrows(ServiceUnavailableException.class,
                () -> client.health());
        assertEquals(Integer.valueOf(503), e.getStatus(), "status");
        assertEquals("service_unavailable", e.getCode(), "code");
    }

    // -- error taxonomy ---------------------------------------------------------

    private record ErrorCase(int status, String serverError,
                             Class<? extends SunderException> expected) {
    }

    private static void testErrorMapping() {
        List<ErrorCase> cases = List.of(
                new ErrorCase(401, "unauthorized", UnauthorizedException.class),
                new ErrorCase(403, "forbidden", ForbiddenException.class),
                new ErrorCase(403, "purpose_not_allowed", PurposeNotAllowedException.class),
                new ErrorCase(403, "audience_mismatch", AudienceMismatchException.class),
                new ErrorCase(404, "not_found", NotFoundException.class),
                new ErrorCase(400, "validation", ValidationException.class),
                new ErrorCase(400, "bad_json", ValidationException.class),
                new ErrorCase(400, "token_invalid", TokenInvalidException.class),
                new ErrorCase(409, "token_used", TokenUsedException.class),
                new ErrorCase(410, "token_expired", TokenExpiredException.class),
                new ErrorCase(429, "rate_limited", RateLimitedException.class),
                new ErrorCase(500, "internal", ServiceUnavailableException.class),
                new ErrorCase(502, "internal", ServiceUnavailableException.class));
        for (ErrorCase c : cases) {
            mock.reset();
            mock.enqueue(c.status(),
                    "{\"error\":\"" + c.serverError() + "\",\"detail\":\"why it failed\"}");
            // verifyOti never retries, so every case is exactly one round trip;
            // enqueue a second copy anyway so a retry bug shows up as a count failure.
            mock.enqueue(c.status(),
                    "{\"error\":\"" + c.serverError() + "\",\"detail\":\"why it failed\"}");
            SunderException e = expectThrows(c.expected(),
                    () -> client.verifyOti("t", "p", "a"));
            assertEquals(c.expected(), e.getClass(), "exception class for " + c);
            assertEquals(c.serverError(), e.getCode(), "code for " + c);
            assertEquals(Integer.valueOf(c.status()), e.getStatus(), "status for " + c);
            assertEquals("why it failed", e.getDetail(), "detail for " + c);
            assertEquals(1, mock.requests.size(), "single round trip for " + c);
        }
        // The error field wins over the status: token_invalid on 400 is not Validation.
        mock.reset();
        mock.enqueue(400, "{\"error\":\"token_invalid\"}");
        TokenInvalidException ti = expectThrows(TokenInvalidException.class,
                () -> client.verifyOti("t", "p", "a"));
        assertEquals("token_invalid", ti.getCode(), "code precedence");
    }

    private static void testErrorMappingNoBody() {
        mock.enqueue(404, "not json at all");
        NotFoundException e = expectThrows(NotFoundException.class,
                () -> client.lookupByEmail("nobody@example.com"));
        assertEquals("http_404", e.getCode(), "synthetic code");
        assertEquals(Integer.valueOf(404), e.getStatus(), "status");
        assertEquals(null, e.getDetail(), "detail");

        mock.reset();
        mock.enqueue(503, "");
        mock.enqueue(503, "");
        ServiceUnavailableException s = expectThrows(ServiceUnavailableException.class,
                () -> client.lookupByEmail("nobody@example.com"));
        assertEquals("service_unavailable", s.getCode(), "synthetic 5xx code");
        assertEquals(Integer.valueOf(503), s.getStatus(), "status");
    }

    private static void testUnknownStatus() {
        mock.enqueue(418, "{\"error\":\"teapot\"}");
        SunderException e = expectThrows(SunderException.class,
                () -> client.verifyOti("t", "p", "a"));
        assertEquals(SunderException.class, e.getClass(), "base class exactly");
        assertEquals("teapot", e.getCode(), "code");
        assertEquals(Integer.valueOf(418), e.getStatus(), "status");
    }

    // -- retry policy -------------------------------------------------------------

    private static void testLookupRetriesOnce() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        mock.enqueue(200, "{\"cid\":\"CID-retry\"}");
        assertEquals("CID-retry", client.lookupByEmail("filip@example.com"), "cid after retry");
        assertEquals(2, mock.requests.size(), "exactly two attempts");
    }

    private static void testIssueOtiRetriesOnce() {
        mock.enqueue(502, "{\"error\":\"internal\"}");
        mock.enqueue(201, "{\"token\":\"v4.public.r\",\"expires_at\":\"2026-08-22T10:00:00Z\"}");
        OtiResult oti = client.issueOti("CID-abc", "create_order", "erp");
        assertEquals("v4.public.r", oti.token(), "token after retry");
        assertEquals(2, mock.requests.size(), "exactly two attempts");
    }

    private static void testRetryStopsAfterSecondFailure() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        mock.enqueue(500, "{\"error\":\"internal\"}");
        mock.enqueue(200, "{\"cid\":\"CID-never\"}"); // must never be reached
        ServiceUnavailableException e = expectThrows(ServiceUnavailableException.class,
                () -> client.lookupByPhone("+385911234567"));
        assertEquals(Integer.valueOf(500), e.getStatus(), "status of last attempt");
        assertEquals(2, mock.requests.size(), "exactly two attempts, never a third");
    }

    private static void testRegisterNeverRetries() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        expectThrows(ServiceUnavailableException.class,
                () -> client.registerContact(Map.of("email", "filip@example.com")));
        assertEquals(1, mock.requests.size(), "single attempt");
    }

    private static void testIssueScopedCidNeverRetries() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        expectThrows(ServiceUnavailableException.class,
                () -> client.issueScopedCid("CID-abc", "billing"));
        assertEquals(1, mock.requests.size(), "single attempt");
    }

    private static void testGetAttributeNeverRetries() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        expectThrows(ServiceUnavailableException.class,
                () -> client.getAttribute("CID-abc", "email", "support"));
        assertEquals(1, mock.requests.size(), "single attempt");
    }

    private static void testVerifyOtiNeverRetries5xx() {
        mock.enqueue(500, "{\"error\":\"internal\"}");
        mock.enqueue(200, "{\"cid\":\"CID-never\"}"); // a retry bug would consume this
        ServiceUnavailableException e = expectThrows(ServiceUnavailableException.class,
                () -> client.verifyOti("v4.public.xyz", "create_order", "erp"));
        assertEquals(Integer.valueOf(500), e.getStatus(), "status");
        assertEquals(1, mock.requests.size(), "verifyOti must make exactly one attempt");
    }

    private static void testVerifyOtiNeverRetriesTimeout() {
        SunderClient fast = new SunderClient(mock.baseUrl(), "test_client.test_secret",
                Duration.ofMillis(250));
        mock.enqueueSlow(200, "{\"cid\":\"CID-slow\"}", 1500);
        mock.enqueue(200, "{\"cid\":\"CID-never\"}"); // a retry bug would consume this
        ServiceUnavailableException e = expectThrows(ServiceUnavailableException.class,
                () -> fast.verifyOti("v4.public.xyz", "create_order", "erp"));
        assertEquals(null, e.getStatus(), "network failure has no HTTP status");
        assertEquals("service_unavailable", e.getCode(), "code");
        waitForRequests(1);
        assertEquals(1, mock.requests.size(), "verifyOti must make exactly one attempt");
    }

    private static void testLookupRetriesOnTimeout() {
        SunderClient fast = new SunderClient(mock.baseUrl(), "test_client.test_secret",
                Duration.ofMillis(250));
        mock.enqueueSlow(200, "{\"cid\":\"CID-slow\"}", 1500);
        mock.enqueue(200, "{\"cid\":\"CID-after-timeout\"}");
        assertEquals("CID-after-timeout", fast.lookupByEmail("filip@example.com"),
                "cid after network-failure retry");
        waitForRequests(2);
        assertEquals(2, mock.requests.size(), "exactly two attempts");
    }

    /** The slow handler may still be recording; wait briefly for the count. */
    private static void waitForRequests(int expected) {
        long deadline = System.currentTimeMillis() + 3000;
        while (mock.requests.size() < expected && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private static void testNetworkFailure() {
        int deadPort;
        try (ServerSocket s = new ServerSocket(0)) {
            deadPort = s.getLocalPort();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        SunderClient dead = new SunderClient("http://127.0.0.1:" + deadPort,
                "test_client.test_secret", Duration.ofMillis(500));
        ServiceUnavailableException e = expectThrows(ServiceUnavailableException.class,
                () -> dead.lookupByEmail("filip@example.com"));
        assertEquals("service_unavailable", e.getCode(), "code");
        assertEquals(null, e.getStatus(), "status is null for network failures");
        assertTrue(e.getDetail() != null && e.getDetail().startsWith("network failure"),
                "detail describes the network failure");
    }

    // -- config -------------------------------------------------------------------

    private static void testTrailingSlash() {
        SunderClient slashy = new SunderClient(mock.baseUrl() + "///", "test_client.test_secret");
        mock.enqueue(200, "{\"cid\":\"CID-s\"}");
        assertEquals("CID-s", slashy.lookupByEmail("filip@example.com"), "cid");
        assertEquals("/v1/lookup", mock.only().path(), "path without doubled slash");
    }

    private static void testBadResponseBody() {
        mock.enqueue(200, "this is not json");
        SunderException e = expectThrows(SunderException.class,
                () -> client.lookupByEmail("filip@example.com"));
        assertEquals("bad_response", e.getCode(), "code");
        assertEquals(null, e.getStatus(), "status");
    }

    /**
     * Env-var configuration cannot be tested in-process (the JVM cannot set its
     * own environment), so the runner re-executes itself as a child JVM with
     * SUNDER_URL / SUNDER_CREDENTIAL pointed at the mock server.
     */
    private static void testEnvConfig() {
        mock.enqueue(200, "{\"cid\":\"CID-env\"}");
        ProcessResult r = runChild("env-child",
                Map.of("SUNDER_URL", mock.baseUrl(), "SUNDER_CREDENTIAL", "env_client.env_secret"));
        assertEquals(0, r.exitCode(), "child exit code (output: " + r.output() + ")");
        assertTrue(r.output().contains("ENV-CHILD-OK CID-env"), "child output: " + r.output());
        Recorded req = mock.only();
        assertEquals("Bearer env_client.env_secret", req.authorization(),
                "Authorization from env credential");
        assertEquals("/v1/lookup", req.path(), "path");
    }

    private static void testMissingConfig() {
        ProcessResult r = runChild("env-missing-child", Map.of());
        assertEquals(0, r.exitCode(), "child exit code (output: " + r.output() + ")");
        assertTrue(r.output().contains("MISSING-URL-OK"), "missing URL rejected: " + r.output());
        assertTrue(r.output().contains("MISSING-CREDENTIAL-OK"),
                "missing credential rejected: " + r.output());
    }

    private record ProcessResult(int exitCode, String output) {
    }

    private static ProcessResult runChild(String arg, Map<String, String> env) {
        try {
            String java = System.getProperty("java.home") + "/bin/java";
            ProcessBuilder pb = new ProcessBuilder(java,
                    "-cp", System.getProperty("java.class.path"),
                    SunderClientTest.class.getName(), arg);
            pb.environment().remove("SUNDER_URL");
            pb.environment().remove("SUNDER_CREDENTIAL");
            pb.environment().putAll(env);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int code = p.waitFor();
            return new ProcessResult(code, output);
        } catch (Exception e) {
            throw new AssertionError("child process failed: " + e, e);
        }
    }

    /** Child mode: build the client purely from the environment and call lookup. */
    private static void envChild() {
        SunderClient envClient = new SunderClient();
        String cid = envClient.lookupByEmail("filip@example.com");
        System.out.println("ENV-CHILD-OK " + cid);
    }

    /** Child mode: with no env at all, construction must fail fast. */
    private static void envMissingChild() {
        try {
            new SunderClient();
            System.out.println("MISSING-URL-FAILED: no exception");
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("SUNDER_URL")) {
                System.out.println("MISSING-URL-OK");
            } else {
                System.out.println("MISSING-URL-FAILED: " + e.getMessage());
            }
        }
        try {
            new SunderClient("http://127.0.0.1:1", null);
            System.out.println("MISSING-CREDENTIAL-FAILED: no exception");
        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("SUNDER_CREDENTIAL")) {
                System.out.println("MISSING-CREDENTIAL-OK");
            } else {
                System.out.println("MISSING-CREDENTIAL-FAILED: " + e.getMessage());
            }
        }
    }
}
