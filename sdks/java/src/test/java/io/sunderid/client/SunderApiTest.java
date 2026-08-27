package io.sunderid.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * The routes beyond the core handoff surface: consent, data-subject rights,
 * value tokenization, the file vault, shares, links, version history,
 * external claims and the admin unlock.
 *
 * Each test asserts the wire contract and the properties a client can get
 * wrong: an empty cascade must not be sent as an opt-in, bulk routes must
 * carry the unlock token, and destructive calls are never blind-retried.
 *
 * Same plain-Java runner as SunderClientTest - no JUnit, no dependencies.
 */
public final class SunderApiTest {

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

    // -- mock server ------------------------------------------------------------

    /** One recorded inbound request; headers included, which the unlock-gated
     *  routes and the multipart upload are asserted on. */
    private record Recorded(String method, String path, String query,
                            Map<String, String> headers, String body) {
    }

    private record Scripted(int status, String body, String contentType) {
    }

    private static final class MockServer {
        final HttpServer server;
        final List<Recorded> requests = new CopyOnWriteArrayList<>();
        final Deque<Scripted> responses = new ArrayDeque<>();

        MockServer() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", this::handle);
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
            server.start();
        }

        String baseUrl() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        synchronized void enqueue(int status, String body) {
            responses.add(new Scripted(status, body, "application/json"));
        }

        synchronized void enqueueRaw(int status, String body) {
            responses.add(new Scripted(status, body, "application/octet-stream"));
        }

        synchronized void reset() {
            requests.clear();
            responses.clear();
        }

        private void handle(HttpExchange exchange) throws java.io.IOException {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> headers = new java.util.LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((k, v) ->
                    headers.put(k.toLowerCase(java.util.Locale.ROOT), v.isEmpty() ? "" : v.get(0)));
            requests.add(new Recorded(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestURI().getRawQuery(),
                    headers,
                    body));
            Scripted scripted;
            synchronized (this) {
                scripted = responses.poll();
            }
            if (scripted == null) {
                scripted = new Scripted(500, "{\"error\":\"internal\"}", "application/json");
            }
            byte[] out = scripted.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", scripted.contentType());
            exchange.sendResponseHeaders(scripted.status(), out.length);
            try (java.io.OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        }
    }

    private static MockServer mock;
    private static SunderClient client;

    private static Recorded only() {
        assertEquals(1, mock.requests.size(), "expected exactly one request");
        return mock.requests.get(0);
    }

    public static void main(String[] args) throws Exception {
        mock = new MockServer();
        client = new SunderClient(mock.baseUrl(), "test_client.test_secret");

        run("setConsent sends a real boolean", SunderApiTest::testSetConsent);
        run("getConsent decodes the list", SunderApiTest::testGetConsent);
        run("dsrAccess carries holdings beyond the blob", SunderApiTest::testDsrAccess);
        run("dsrExport is caller-scope only", SunderApiTest::testDsrExport);
        run("erase omits cascade unless asked", SunderApiTest::testEraseNoCascade);
        run("erase forwards named link types", SunderApiTest::testEraseCascade);
        run("erase is never retried", SunderApiTest::testEraseNotRetried);
        run("tokenize omits an unset cid", SunderApiTest::testTokenize);
        run("detokenize and delete", SunderApiTest::testDetokenizeAndDelete);
        run("deleteToken is not retried", SunderApiTest::testDeleteTokenNotRetried);
        run("bulk routes carry the unlock token", SunderApiTest::testBulkUnlockHeader);
        run("bulk read is not retried", SunderApiTest::testBulkNotRetried);
        run("upload sends multipart with filename and expiry", SunderApiTest::testUpload);
        run("upload omits the expiry header when null", SunderApiTest::testUploadNoExpiry);
        run("listFiles sends the purpose", SunderApiTest::testListFiles);
        run("download returns bytes and maps errors", SunderApiTest::testDownload);
        run("createShare sends the partner label", SunderApiTest::testCreateShare);
        run("fetch and revoke share", SunderApiTest::testFetchRevokeShare);
        run("links round-trip", SunderApiTest::testLinks);
        run("historical read still sends the purpose", SunderApiTest::testVersions);
        run("external claim keeps issuer provenance", SunderApiTest::testExternalClaim);
        run("unlock mints a single-use token", SunderApiTest::testUnlock);
        run("userId is sent on every call", SunderApiTest::testUserIdHeader);

        mock.server.stop(0);
        System.out.println();
        System.out.println(passed + " passed, " + failures.size() + " failed");
        if (!failures.isEmpty()) {
            failures.forEach(f -> System.out.println("  " + f));
            System.exit(1);
        }
        // The mock's cached thread pool holds non-daemon threads, so stopping
        // the server is not enough to end the JVM - without this the runner
        // hangs after the last PASS line instead of exiting 0.
        System.exit(0);
    }

    // -- consent ------------------------------------------------------------------

    private static void testSetConsent() {
        mock.enqueue(200, "{\"cid\":\"CID1\",\"purpose\":\"billing\",\"granted\":false}");
        Map<String, Object> out = client.setConsent("CID1", "billing", false);
        assertEquals(Boolean.FALSE, out.get("granted"), "granted");
        assertTrue(only().body().contains("\"granted\":false"),
                "granted must reach the server as a JSON boolean");
    }

    private static void testGetConsent() {
        mock.enqueue(200, "{\"consents\":[{\"purpose\":\"billing\",\"granted\":true}]}");
        List<Map<String, Object>> got = client.getConsent("CID1");
        assertEquals(1, got.size(), "consent count");
        assertEquals("/v1/consent/CID1", only().path(), "path");
    }

    // -- data subject rights --------------------------------------------------------

    private static void testDsrAccess() {
        mock.enqueue(200, "{\"scopes\":[{\"scope\":\"crm\",\"cid\":\"CID1\","
                + "\"value_tokens\":[{\"token\":\"tok_1\"}],"
                + "\"files\":[{\"id\":\"f1\"}],"
                + "\"shares\":[{\"uuid\":\"u1\",\"partner_label\":\"partner-bank\"}],"
                + "\"links\":[{\"cid\":\"CID2\",\"link_type\":\"guardian\"}]}],"
                + "\"audit_trail\":[{\"ts\":\"2026-01-01T00:00:00Z\",\"client_id\":\"crm\","
                + "\"action\":\"lookup\",\"count\":3}]}");
        Map<String, Object> out = client.dsrAccess("CID1");
        @SuppressWarnings("unchecked")
        List<Object> scopes = (List<Object>) out.get("scopes");
        assertEquals(1, scopes.size(), "scope count");
        @SuppressWarnings("unchecked")
        Map<String, Object> scope = (Map<String, Object>) scopes.get(0);
        for (String section : new String[] {"value_tokens", "files", "shares", "links"}) {
            assertTrue(scope.get(section) instanceof List<?> l && l.size() == 1,
                    section + " was dropped");
        }
        assertEquals("cid=CID1", only().query(), "query");
    }

    private static void testDsrExport() {
        mock.enqueue(200, "{\"scope\":\"crm\",\"cid\":\"CID1\"}");
        assertEquals("crm", client.dsrExport("CID1").get("scope"), "scope");
        assertEquals("/v1/dsr/export", only().path(), "path");
    }

    private static void testEraseNoCascade() {
        mock.enqueue(200, "{\"erasure_id\":7,\"scopes\":2,"
                + "\"linked\":[{\"cid\":\"CID2\",\"link_type\":\"guardian\",\"cascaded\":false}]}");
        Map<String, Object> out = client.dsrErase("CID1");
        assertEquals(7L, ((Number) out.get("erasure_id")).longValue(), "erasure id");
        assertTrue(!only().body().contains("cascade"),
                "no cascade was requested, so the key must be absent from the body");
    }

    private static void testEraseCascade() {
        mock.enqueue(200, "{\"erasure_id\":8,\"scopes\":1}");
        client.dsrErase("CID1", List.of("guardian"));
        assertTrue(only().body().contains("\"cascade\":[\"guardian\"]"),
                "named link types must reach the server verbatim");
    }

    private static void testEraseNotRetried() {
        mock.enqueue(503, "{\"error\":\"service_unavailable\"}");
        expectThrows(ServiceUnavailableException.class, () -> client.dsrErase("CID1"));
        assertEquals(1, mock.requests.size(), "a destructive call must be attempted exactly once");
    }

    // -- value tokenization ----------------------------------------------------------

    private static void testTokenize() {
        mock.enqueue(201, "{\"token\":\"tok_abc\"}");
        String token = client.tokenize("4111111111111111", Map.of("type", "card", "unique", true));
        assertEquals("tok_abc", token, "token");
        assertTrue(!only().body().contains("\"cid\""),
                "an unset cid must be omitted, not sent empty");
    }

    private static void testDetokenizeAndDelete() {
        mock.enqueue(200, "{\"value\":\"secret\"}");
        assertEquals("secret", client.detokenize("tok_1"), "value");
        mock.reset();
        mock.enqueue(200, "{\"status\":\"deleted\"}");
        client.deleteToken("tok_1");
        assertEquals("DELETE", only().method(), "method");
    }

    private static void testDeleteTokenNotRetried() {
        mock.enqueue(503, "{\"error\":\"service_unavailable\"}");
        expectThrows(ServiceUnavailableException.class, () -> client.deleteToken("tok_1"));
        assertEquals(1, mock.requests.size(), "a destructive call must not be retried");
    }

    private static void testBulkUnlockHeader() {
        mock.enqueue(201, "{\"tokens\":[\"t1\",\"t2\"]}");
        List<String> tokens = client.tokenizeBulk("unlock_xyz",
                List.of(Map.of("value", "a"), Map.of("value", "b")));
        assertEquals(List.of("t1", "t2"), tokens, "tokens");
        assertEquals("unlock_xyz", only().headers().get("x-sunder-unlock"),
                "bulk routes always require an unlock token");
    }

    private static void testBulkNotRetried() {
        // The unlock token is spent by the first attempt: a retry would come
        // back already-used and hide whether the batch landed.
        mock.enqueue(503, "{\"error\":\"service_unavailable\"}");
        expectThrows(ServiceUnavailableException.class,
                () -> client.detokenizeBulk("unlock_xyz", List.of("t1")));
        assertEquals(1, mock.requests.size(), "an unlock-spending call must not be retried");
    }

    // -- file vault --------------------------------------------------------------------

    private static void testUpload() {
        mock.enqueue(201, "{\"id\":\"f1\",\"name\":\"scan.pdf\",\"sha256\":\"deadbeef\"}");
        Map<String, Object> meta = client.uploadFile("CID1", "scan.pdf",
                "hello".getBytes(StandardCharsets.UTF_8), "application/pdf", "2030-01-02T03:04:05Z");
        assertEquals("deadbeef", meta.get("sha256"), "sha256");
        Recorded req = only();
        assertTrue(req.headers().get("content-type").startsWith("multipart/form-data"),
                "upload must be multipart");
        assertTrue(req.body().contains("filename=\"scan.pdf\""), "filename must be in the body");
        assertTrue(req.body().contains("hello"), "content must be in the body");
        assertEquals("2030-01-02T03:04:05Z", req.headers().get("x-sunder-file-expiry"), "expiry header");
    }

    private static void testUploadNoExpiry() {
        mock.enqueue(201, "{\"id\":\"f1\"}");
        client.uploadFile("CID1", "a.txt", "x".getBytes(StandardCharsets.UTF_8), null, null);
        assertEquals(null, only().headers().get("x-sunder-file-expiry"),
                "a null expiry must not send the header at all");
    }

    private static void testListFiles() {
        mock.enqueue(200, "{\"files\":[{\"id\":\"f1\"}]}");
        List<Map<String, Object>> files = client.listFiles("CID1", "support");
        assertEquals(1, files.size(), "file count");
        assertEquals("purpose=support", only().query(), "purpose must be sent as a query parameter");
    }

    private static void testDownload() {
        mock.enqueueRaw(200, "raw-bytes");
        byte[] got = client.downloadFile("f1", "support");
        assertEquals("raw-bytes", new String(got, StandardCharsets.UTF_8), "body");
        mock.reset();
        // A 404 must not reach the caller as bytes of an error page.
        mock.enqueue(404, "{\"error\":\"not_found\"}");
        expectThrows(NotFoundException.class, () -> client.downloadFile("missing", "support"));
    }

    // -- shares, links, versions -----------------------------------------------------------

    private static void testCreateShare() {
        mock.enqueue(201, "{\"uuid\":\"u1\",\"expires_at\":\"2026-01-01T00:00:00Z\"}");
        Map<String, Object> share = client.createShare("CID1", List.of("email"),
                Map.of("partner_label", "partner-bank"));
        assertEquals("u1", share.get("uuid"), "uuid");
        assertTrue(only().body().contains("partner-bank"),
                "the partner label is what the Article 15 answer reports");
    }

    private static void testFetchRevokeShare() {
        mock.enqueue(200, "{\"fields\":{\"email\":\"a@b.c\"}}");
        assertEquals("a@b.c", client.fetchShare("u1").get("email"), "field");
        mock.reset();
        mock.enqueue(200, "{\"status\":\"revoked\"}");
        client.revokeShare("u1");
        assertEquals("DELETE", only().method(), "revoke must be a DELETE");
    }

    private static void testLinks() {
        mock.enqueue(201, "{\"status\":\"linked\"}");
        client.link("PARENT", "CHILD", "guardian");
        assertTrue(only().body().contains("\"link_type\":\"guardian\""), "link type");
        mock.reset();
        mock.enqueue(200, "{\"links\":[{\"cid\":\"CHILD\",\"link_type\":\"guardian\",\"role\":\"parent\"}]}");
        assertEquals("parent", client.listLinks("PARENT").get(0).get("role"), "role");
        mock.reset();
        mock.enqueue(200, "{\"status\":\"unlinked\"}");
        client.unlink("PARENT", "CHILD");
        assertEquals("DELETE", only().method(), "unlink must be a DELETE");
    }

    private static void testVersions() {
        mock.enqueue(200, "{\"versions\":[{\"version_no\":2,\"written_by\":\"crm\"}]}");
        assertEquals(1, client.listVersions("CID1").size(), "version count");
        mock.reset();
        mock.enqueue(200, "{\"value\":\"old@example.com\"}");
        assertEquals("old@example.com",
                client.getVersionAttribute("CID1", 2, "email", "support"), "historical value");
        // An old value is not a lesser secret.
        assertEquals("/v1/contacts/CID1/versions/2/attributes/email", only().path(), "path");
        assertEquals("purpose=support", only().query(), "purpose");
    }

    // -- claims, unlock, attribution ---------------------------------------------------------

    private static void testExternalClaim() {
        mock.enqueue(200, "{\"stored\":[\"verified_age@gov-id\"]}");
        List<String> stored = client.storeExternalClaim("CID1", "eyJ...envelope");
        assertTrue(stored.get(0).contains("@"), "issuer provenance must survive in the stored name");
        assertTrue(only().body().contains("eyJ...envelope"), "envelope must be forwarded unmodified");
    }

    private static void testUnlock() {
        mock.enqueue(201, "{\"unlock_token\":\"unlock_xyz\",\"expires_at\":\"2026-01-01T00:01:00Z\"}");
        assertEquals("unlock_xyz", client.unlock("tokens").get("unlock_token"), "unlock token");
        assertTrue(only().body().contains("\"purpose\":\"tokens\""), "purpose");
    }

    private static void testUserIdHeader() {
        SunderClient attributed = new SunderClient(mock.baseUrl(), "test_client.test_secret",
                java.time.Duration.ofSeconds(10), "agent-7");
        mock.enqueue(200, "{\"value\":\"a@b.c\"}");
        attributed.getAttribute("CID1", "email", "support");
        assertEquals("agent-7", only().headers().get("x-sunder-user-id"),
                "operator attribution header must be sent");
    }
}
