package io.sunderid.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sunder Java SDK - a thin client for the Sunder pseudonymous identity
 * provider (v1 API).
 *
 * <p>Implements the canonical CidProviderClient interface (docs/DESIGN.md, SDK design rules):
 * transport, auth, timeouts, retries and error mapping only. Zero
 * cryptography, zero runtime dependencies ({@code java.net.http} plus a
 * hand-rolled minimal JSON codec). Java 17+.
 *
 * <p>Retry policy (baked in, the SDK design rules (docs/DESIGN.md)):
 * <ul>
 *   <li>lookups and {@link #issueOti} retry once on 5xx / network errors
 *       (safe);</li>
 *   <li>{@link #verifyOti} is NEVER blind-retried (single-use token - a retry
 *       after an ambiguous network failure would legitimately return
 *       TokenUsed; that outcome is surfaced distinctly for the caller to
 *       decide).</li>
 * </ul>
 *
 * <p>Remember: LOOKUP != AUTHENTICATION - a lookup hit never proves the
 * caller is talking to that person.
 */
public final class SunderClient {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(10);

    private final String baseUrl;
    private final String credential;
    private final Duration timeout;
    private final HttpClient http;

    /**
     * Configures the client entirely from the environment:
     * {@code SUNDER_URL} and {@code SUNDER_CREDENTIAL}, default timeout (10s).
     */
    public SunderClient() {
        this(null, null, DEFAULT_TIMEOUT);
    }

    /**
     * @param url        base URL of the Sunder instance; {@code null} falls
     *                   back to env {@code SUNDER_URL}
     * @param credential {@code "client_id.secret"} bearer credential;
     *                   {@code null} falls back to env {@code SUNDER_CREDENTIAL}
     */
    public SunderClient(String url, String credential) {
        this(url, credential, DEFAULT_TIMEOUT);
    }

    /**
     * @param url        base URL of the Sunder instance; {@code null} falls
     *                   back to env {@code SUNDER_URL}
     * @param credential {@code "client_id.secret"} bearer credential;
     *                   {@code null} falls back to env {@code SUNDER_CREDENTIAL}
     * @param timeout    per-request timeout; {@code null} means the default (10s)
     */
    public SunderClient(String url, String credential, Duration timeout) {
        if (url == null) {
            url = System.getenv("SUNDER_URL");
        }
        if (credential == null) {
            credential = System.getenv("SUNDER_CREDENTIAL");
        }
        if (url == null || url.isEmpty()) {
            throw new IllegalArgumentException("Sunder URL required (arg or SUNDER_URL)");
        }
        if (credential == null || credential.isEmpty()) {
            throw new IllegalArgumentException("Sunder credential required (arg or SUNDER_CREDENTIAL)");
        }
        this.baseUrl = url.replaceAll("/+$", "");
        this.credential = credential;
        this.timeout = timeout != null ? timeout : DEFAULT_TIMEOUT;
        this.http = HttpClient.newBuilder()
                .connectTimeout(this.timeout)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    // -- contacts ------------------------------------------------------------

    /**
     * Registers (or dedup-merges) a contact; returns the caller-scope CID.
     *
     * <p>{@code attributes} is the full request body: email/phone/name values
     * (plus the plural {@code "emails"}/{@code "phones"} lists for contacts
     * with several searchable identifiers) and an optional nested
     * {@code "attributes"} map of custom fields.
     */
    public String registerContact(Map<String, Object> attributes) {
        return requireString(request("POST", "/v1/contacts", attributes, false), "cid");
    }

    /**
     * Issues the same person's CID in another scope. Linkage-capable - grant
     * sparingly; prefer OTIs for cross-system handoff.
     */
    public String issueScopedCid(String cid, String scope) {
        String path = "/v1/contacts/" + encode(cid) + "/scopes";
        return requireString(request("POST", path, Map.of("scope", scope), false), "cid");
    }

    // -- lookup (LOOKUP != AUTHENTICATION) -------------------------------------

    /** Finds a contact by email; returns the caller-scope CID. Retries once on 5xx. */
    public String lookupByEmail(String email) {
        return requireString(request("POST", "/v1/lookup", Map.of("email", email), true), "cid");
    }

    /** Finds a contact by phone; returns the caller-scope CID. Retries once on 5xx. */
    public String lookupByPhone(String phone) {
        return requireString(request("POST", "/v1/lookup", Map.of("phone", phone), true), "cid");
    }

    /**
     * Finds a contact by name plus a second factor (email or phone).
     *
     * <p>A name alone is never an identifier; exactly the API's rule is
     * enforced client-side: at least one of email/phone is required.
     */
    public String lookupByName(String name, String email, String phone) {
        if (email == null && phone == null) {
            throw new ValidationException("validation", null,
                    "lookupByName requires email or phone as a second factor");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("name", name);
        if (email != null) {
            body.put("email", email);
        }
        if (phone != null) {
            body.put("phone", phone);
        }
        return requireString(request("POST", "/v1/lookup", body, true), "cid");
    }

    // -- attributes ------------------------------------------------------------

    /**
     * Fetches exactly one attribute value; {@code purpose} is mandatory and
     * must be in the caller's allowed purposes. Every fetch is audited
     * server-side.
     */
    public String getAttribute(String cid, String name, String purpose) {
        String path = "/v1/contacts/" + encode(cid) + "/attributes/" + encode(name)
                + "?purpose=" + encode(purpose);
        return requireString(request("GET", path, null, false), "value");
    }

    // -- OTI ---------------------------------------------------------------

    /**
     * Issues a one-time identifier: 5 minutes, one use, one audience, one
     * purpose. Safe to retry (retries once on 5xx / network failure).
     */
    public OtiResult issueOti(String cid, String purpose, String audience) {
        return issueOti(cid, purpose, audience, null);
    }

    /**
     * Variant with issuer-authorized attribute sharing: the listed
     * attributes are copied into the verifier's scope at verification.
     */
    public OtiResult issueOti(String cid, String purpose, String audience, java.util.List<String> shareAttributes) {
        return issueOti(cid, purpose, audience, shareAttributes, null);
    }

    /**
     * Variant with predicate claims: each map is
     * {"attr": "birthdate", "op": "age_gte", "value": 18} or
     * {"attr": "tier", "op": "exists"}. Evaluated against the issuer's data
     * at verification; the verifier receives booleans only, never the value.
     */
    public OtiResult issueOti(String cid, String purpose, String audience,
                              java.util.List<String> shareAttributes,
                              java.util.List<Map<String, Object>> sharePredicates) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cid", cid);
        body.put("purpose", purpose);
        body.put("audience", audience);
        if (shareAttributes != null && !shareAttributes.isEmpty()) {
            body.put("share_attributes", shareAttributes);
        }
        if (sharePredicates != null && !sharePredicates.isEmpty()) {
            body.put("share_predicates", sharePredicates);
        }
        Map<String, Object> raw = request("POST", "/v1/oti", body, true);
        return new OtiResult(requireString(raw, "token"), requireString(raw, "expires_at"));
    }

    /**
     * Verifies and consumes a one-time identifier; returns the VERIFIER's own
     * scoped CID. NEVER blind-retried: the token is single-use, so a retry
     * after an ambiguous network failure would legitimately return TokenUsed.
     * On TokenUsed after a failure, the caller decides how to reconcile.
     */
    public String verifyOti(String token, String purpose, String audience) {
        return requireString(verifyOtiFull(token, purpose, audience), "cid");
    }

    /**
     * Like {@link #verifyOti} but returns the full result map: "cid", and
     * when present "shared" (copied attribute names) and "predicates" (each
     * a map with attr/op/value/result/known). For age_gte, known=false means
     * the attribute was absent or unparseable - NOT a failed check; for
     * exists, known is always true because absence is the answer.
     */
    public Map<String, Object> verifyOtiFull(String token, String purpose, String audience) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token);
        body.put("purpose", purpose);
        body.put("audience", audience);
        // Single-use token - see method doc: never blind-retried.
        return request("POST", "/v1/oti/verify", body, false);
    }

    // -- ops -------------------------------------------------------------------

    /** Liveness probe (unauthenticated GET /healthz); returns the status text. */
    public String health() {
        HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/healthz"))
                .timeout(timeout)
                .GET()
                .build();
        HttpResponse<String> res;
        try {
            res = http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new ServiceUnavailableException("service_unavailable", null,
                    "network failure: " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServiceUnavailableException("service_unavailable", null,
                    "network failure: " + e);
        }
        if (res.statusCode() < 200 || res.statusCode() >= 300) {
            throw mapError(res.statusCode(), res.body());
        }
        String body = res.body().trim();
        return body.isEmpty() ? "ok" : body;
    }

    // -- transport -------------------------------------------------------------

    /**
     * One HTTP round trip; a single extra attempt when {@code retryOnce} is
     * set and the failure is a 5xx or a network error.
     */
    private Map<String, Object> request(String method, String path,
                                        Map<String, Object> body, boolean retryOnce) {
        int attempts = retryOnce ? 2 : 1;
        ServiceUnavailableException lastError = null;
        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                return doRequest(method, path, body);
            } catch (ServiceUnavailableException e) {
                lastError = e; // retryable if attempts remain
                if (Thread.currentThread().isInterrupted()) {
                    // A thread interrupt is a cancellation, not a service
                    // failure: never issue another network attempt for it.
                    throw lastError;
                }
            }
        }
        throw lastError;
    }

    private Map<String, Object> doRequest(String method, String path, Map<String, Object> body) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + credential)
                .header("Accept", "application/json");
        if (body != null) {
            builder.header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(
                            Json.write(body), StandardCharsets.UTF_8));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> res;
        try {
            res = http.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new ServiceUnavailableException("service_unavailable", null,
                    "network failure: " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServiceUnavailableException("service_unavailable", null,
                    "network failure: " + e);
        }
        int status = res.statusCode();
        if (status < 200 || status >= 300) {
            throw mapError(status, res.body());
        }
        try {
            return Json.parseObject(res.body());
        } catch (Json.JsonException e) {
            throw new SunderException("bad_response", null, "non-JSON response body");
        }
    }

    /** Builds the taxonomy exception for a non-2xx response. */
    private static SunderException mapError(int status, String body) {
        String code = "";
        String detail = null;
        try {
            Map<String, Object> parsed = Json.parseObject(body);
            Object c = parsed.get("error");
            if (c != null) {
                code = String.valueOf(c);
            }
            Object d = parsed.get("detail");
            if (d != null) {
                detail = String.valueOf(d);
            }
        } catch (RuntimeException ignored) {
            // Non-JSON error body - fall through to status-only mapping.
        }
        if (status >= 500) {
            return new ServiceUnavailableException(
                    code.isEmpty() ? "service_unavailable" : code, status, detail);
        }
        String effective = code.isEmpty() ? "http_" + status : code;
        // Exact error-code pairs first; falls through to status-only rules.
        switch (code) {
            case "unauthorized":
                return new UnauthorizedException(effective, status, detail);
            case "forbidden":
                return new ForbiddenException(effective, status, detail);
            case "credential_expired":
                return new CredentialExpiredException(effective, status, detail);
            case "consent_denied":
                return new ConsentDeniedException(effective, status, detail);
            case "purpose_not_allowed":
                return new PurposeNotAllowedException(effective, status, detail);
            case "unlock_required":
                return new UnlockRequiredException(effective, status, detail);
            case "audience_mismatch":
                return new AudienceMismatchException(effective, status, detail);
            case "not_found":
                return new NotFoundException(effective, status, detail);
            case "validation":
            case "bad_json":
                return new ValidationException(effective, status, detail);
            case "token_invalid":
                return new TokenInvalidException(effective, status, detail);
            case "token_used":
                return new TokenUsedException(effective, status, detail);
            case "token_expired":
                return new TokenExpiredException(effective, status, detail);
            case "rate_limited":
                return new RateLimitedException(effective, status, detail);
            default:
                break;
        }
        switch (status) {
            case 400:
                return new ValidationException(effective, status, detail);
            case 401:
                return new UnauthorizedException(effective, status, detail);
            case 403:
                return new ForbiddenException(effective, status, detail);
            case 404:
                return new NotFoundException(effective, status, detail);
            case 409:
                return new TokenUsedException(effective, status, detail);
            case 410:
                return new TokenExpiredException(effective, status, detail);
            case 429:
                return new RateLimitedException(effective, status, detail);
            default:
                return new SunderException(effective, status, detail);
        }
    }

    private static String requireString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (!(value instanceof String s)) {
            throw new SunderException("bad_response", null,
                    "missing \"" + key + "\" in response");
        }
        return s;
    }

    /** Percent-encodes one path segment or query value (RFC 3986, nothing safe). */
    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
