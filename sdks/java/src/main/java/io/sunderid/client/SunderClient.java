package io.sunderid.client;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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
    private final String userId;

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
        this(url, credential, timeout, null);
    }

    /**
     * @param url        base URL of the Sunder instance; {@code null} falls
     *                   back to env {@code SUNDER_URL}
     * @param credential {@code "client_id.secret"} bearer credential;
     *                   {@code null} falls back to env {@code SUNDER_CREDENTIAL}
     * @param timeout    per-request timeout; {@code null} means the default (10s)
     * @param userId     attributes every read to an operator inside the calling
     *                   system, sent as {@code X-Sunder-User-Id} and recorded in
     *                   the audit chain. CLIENT-ASSERTED and unverifiable by
     *                   design: Sunder records the claim and proves it was not
     *                   altered afterwards, not that it was true. Accepts
     *                   {@code [A-Za-z0-9._@:-]}, 1-64 characters; anything else
     *                   is a 400 rather than a silent drop.
     */
    public SunderClient(String url, String credential, Duration timeout, String userId) {
        this.userId = userId;
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


    // -- consent ---------------------------------------------------------------

    /**
     * Records the person's decision for one purpose.
     *
     * <p>Consent gates attribute reads for that purpose: revoking it makes
     * {@link #getAttribute} throw {@link ConsentDeniedException} even though
     * the client's own grant is unchanged. Every call is appended to the audit
     * chain, and that trail SURVIVES erasure - it is the accountability record
     * of what was consented to and when.
     */
    public Map<String, Object> setConsent(String cid, String purpose, boolean granted) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cid", cid);
        body.put("purpose", purpose);
        body.put("granted", granted);
        return request("POST", "/v1/consent", body, false);
    }

    /**
     * Lists every purpose the caller's scope has recorded for a person.
     *
     * <p>A purpose that was never set is ABSENT, not false: "no decision" and
     * "refused" are different facts.
     */
    public List<Map<String, Object>> getConsent(String cid) {
        return listOf(request("GET", "/v1/consent/" + encode(cid), null, true), "consents");
    }

    // -- data subject rights -----------------------------------------------------

    /**
     * Article 15, ORG-WIDE: {@code {"scopes": [...], "audit_trail": [...]}}.
     *
     * <p>Each scope carries the holdings that do NOT live in the attribute blob -
     * value tokens, files, the RECIPIENTS of shares, and links. This crosses
     * scope boundaries on the data subject's behalf, so it needs its own grant
     * and is itself audited; never route it through an ordinary integration
     * credential.
     */
    public Map<String, Object> dsrAccess(String cid) {
        return request("GET", "/v1/dsr/access?cid=" + encode(cid), null, true);
    }

    /**
     * Article 20 for the CALLER's scope only: the same holdings sections in
     * machine-readable form, for portability.
     */
    public Map<String, Object> dsrExport(String cid) {
        return request("GET", "/v1/dsr/export?cid=" + encode(cid), null, true);
    }

    /** Article 17 erasure with no cascade: linked children are listed, not touched. */
    public Map<String, Object> dsrErase(String cid) {
        return dsrErase(cid, null);
    }

    /**
     * Article 17: erases the person org-wide, queueing one Article 19
     * notification per scope that held them.
     *
     * <p>{@code cascade} names the link types ("guardian", "member", "owner")
     * whose linked children are erased too. Null or empty, the children are
     * LISTED in the result and left untouched - an accidental cascade would
     * delete a third party's data, so it is opt-in per link type.
     *
     * <p>A cascade is one transaction PER PERSON, and the plan is recorded
     * before any child is touched: re-issuing the identical call after an
     * interruption RESUMES the outstanding children. Once everything is done it
     * throws {@link NotFoundException}, deliberately indistinguishable from a
     * cid that never existed.
     *
     * <p>Never retried: it is destructive, and resuming is the caller's decision.
     */
    public Map<String, Object> dsrErase(String cid, List<String> cascade) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cid", cid);
        // An empty list must not be sent: absence is what "cascade nothing"
        // looks like on the wire.
        if (cascade != null && !cascade.isEmpty()) {
            body.put("cascade", cascade);
        }
        return request("POST", "/v1/dsr/erase", body, false);
    }

    // -- value tokenization -------------------------------------------------------

    /**
     * Vaults one value and returns its opaque token.
     *
     * <p>{@code options} accepts {@code "type"} ("string" default, or "card"
     * which also validates the Luhn checksum), {@code "cid"}, {@code "unique"},
     * {@code "expires_final"} and {@code "sliding_seconds"}. The cid binds the
     * token to a person in the caller's scope, so erasure and the retention
     * sweep destroy it; omit it ONLY for a scope-wide value belonging to no
     * single subject, because an unattributed token survives that erasure.
     */
    public String tokenize(String value, Map<String, Object> options) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("value", value);
        if (options != null) {
            body.putAll(options);
        }
        return requireString(request("POST", "/v1/tokens", body, false), "token");
    }

    /** Vaults one value with no options. */
    public String tokenize(String value) {
        return tokenize(value, null);
    }

    /**
     * Resolves a token back to its value.
     *
     * <p>Audited per read and, for a cid-bound token, attributed to that
     * person's CID - so "who read my tokenized IBAN" is answerable from the
     * access trail.
     */
    public String detokenize(String token) {
        return requireString(request("GET", "/v1/tokens/" + encode(token), null, true), "value");
    }

    /** Destroys a token and its value. Not retried: it is destructive. */
    public void deleteToken(String token) {
        request("DELETE", "/v1/tokens/" + encode(token), null, false);
    }

    /**
     * Vaults many values in one call; tokens come back in input order.
     *
     * <p>Bulk surfaces ALWAYS require a single-use unlock token, regardless of
     * {@code SUNDER_SEARCH_UNLOCK}: one call touching many people is exactly the
     * shape a rate limit does not constrain. Get one from {@link #unlock}. The
     * whole batch is validated before the token is spent, so a rejected item
     * does not burn the unlock.
     */
    public List<String> tokenizeBulk(String unlockToken, List<Map<String, Object>> items) {
        Map<String, Object> out = request("POST", "/v1/tokens/bulk",
                Map.of("items", items), false,
                Map.of("X-Sunder-Unlock", unlockToken), null);
        return stringsOf(out, "tokens");
    }

    /** Resolves many tokens in one call. Requires an unlock token. */
    public List<String> detokenizeBulk(String unlockToken, List<String> tokens) {
        Map<String, Object> out = request("POST", "/v1/tokens/bulk/read",
                Map.of("tokens", tokens), false,
                Map.of("X-Sunder-Unlock", unlockToken), null);
        return stringsOf(out, "values");
    }

    // -- file vault ----------------------------------------------------------------

    /**
     * Stores a file for a person; returns its metadata.
     *
     * <p>Each file gets its own data key, wrapped by the person's record key -
     * so erasing the person shreds the file even if the object store still holds
     * the ciphertext. {@code expiresAt} (RFC 3339, may be null) sets a hard
     * deadline after which the file is unreadable and swept.
     *
     * <p>Never retried: a retried upload after an ambiguous failure stores the
     * file twice.
     */
    public Map<String, Object> uploadFile(String cid, String filename, byte[] content,
                                          String contentType, String expiresAt) {
        String boundary = "----SunderFormBoundary" + Long.toHexString(System.nanoTime())
                + Integer.toHexString(filename.hashCode());
        String head = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
                + "Content-Type: " + (contentType == null ? "application/octet-stream" : contentType)
                + "\r\n\r\n";
        String tail = "\r\n--" + boundary + "--\r\n";
        byte[] headBytes = head.getBytes(StandardCharsets.UTF_8);
        byte[] tailBytes = tail.getBytes(StandardCharsets.UTF_8);
        byte[] payload = new byte[headBytes.length + content.length + tailBytes.length];
        System.arraycopy(headBytes, 0, payload, 0, headBytes.length);
        System.arraycopy(content, 0, payload, headBytes.length, content.length);
        System.arraycopy(tailBytes, 0, payload, headBytes.length + content.length, tailBytes.length);

        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "multipart/form-data; boundary=" + boundary);
        if (expiresAt != null) {
            headers.put("X-Sunder-File-Expiry", expiresAt);
        }
        return request("POST", "/v1/contacts/" + encode(cid) + "/files", null, false,
                headers, payload);
    }

    /**
     * Lists a person's files (metadata only). Purpose-gated and consent-gated
     * like any other read; expired files are hidden.
     */
    public List<Map<String, Object>> listFiles(String cid, String purpose) {
        String path = "/v1/contacts/" + encode(cid) + "/files?purpose=" + encode(purpose);
        return listOf(request("GET", path, null, true), "files");
    }

    /**
     * Downloads one file's plaintext.
     *
     * <p>A download that fails mid-stream ABORTS the connection rather than
     * completing a 200 with a short body, so a truncated read surfaces as a
     * network error - verify the length, or the {@code sha256} from
     * {@link #listFiles}, before treating the bytes as complete.
     */
    public byte[] downloadFile(String id, String purpose) {
        String path = "/v1/files/" + encode(id) + "?purpose=" + encode(purpose);
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + credential)
                .GET();
        if (userId != null) {
            builder.header("X-Sunder-User-Id", userId);
        }
        HttpResponse<byte[]> res;
        try {
            res = http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException e) {
            throw new ServiceUnavailableException("service_unavailable", null, "network failure: " + e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ServiceUnavailableException("service_unavailable", null, "network failure: " + e);
        }
        int status = res.statusCode();
        if (status < 200 || status >= 300) {
            // A 404 must surface as the taxonomy error, never as the bytes of
            // an error page the caller would write to disk as the file.
            throw mapError(status, new String(res.body(), StandardCharsets.UTF_8));
        }
        return res.body();
    }

    /**
     * Removes a file. Its name and digest are redacted immediately; the
     * ciphertext is collected by the retention sweep. Not retried.
     */
    public void deleteFile(String id) {
        request("DELETE", "/v1/files/" + encode(id), null, false);
    }

    // -- cross-org shares -------------------------------------------------------------

    /**
     * Discloses a SNAPSHOT of named fields to a partner.
     *
     * <p>The returned uuid is unguessable and, when the server runs with
     * {@code SUNDER_SHARES_PUBLIC}, is the ONLY credential needed to fetch it -
     * treat it as a bearer secret. {@code options} accepts
     * {@code "partner_label"} (which identifies the recipient in the audit trail
     * and in the Article 15 answer), {@code "purpose"} and {@code "ttl_seconds"}.
     */
    public Map<String, Object> createShare(String cid, List<String> fields,
                                           Map<String, Object> options) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cid", cid);
        body.put("fields", fields);
        if (options != null) {
            body.putAll(options);
        }
        return request("POST", "/v1/shares", body, false);
    }

    /**
     * Reads a share's fields. An expired, revoked or erased share throws
     * {@link NotFoundException}.
     */
    public Map<String, Object> fetchShare(String uuid) {
        Map<String, Object> out = request("GET", "/v1/shares/" + encode(uuid), null, true);
        Object fields = out.get("fields");
        if (fields instanceof Map<?, ?> m) {
            Map<String, Object> typed = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                typed.put(String.valueOf(e.getKey()), e.getValue());
            }
            return typed;
        }
        return new LinkedHashMap<>();
    }

    /**
     * Withdraws a share. Precise to (cid, purpose) on the consent path, so
     * revoking one never silently withdraws another. Not retried.
     */
    public void revokeShare(String uuid) {
        request("DELETE", "/v1/shares/" + encode(uuid), null, false);
    }

    // -- person links --------------------------------------------------------------------

    /**
     * Relates two people in the caller's scope.
     *
     * <p>Erasing the parent LISTS the children; it never erases them unless
     * {@link #dsrErase(String, List)} names the link type.
     */
    public void link(String parentCid, String childCid, String linkType) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("parent_cid", parentCid);
        body.put("child_cid", childCid);
        body.put("link_type", linkType);
        request("POST", "/v1/links", body, false);
    }

    /** Removes the relation. Not retried. */
    public void unlink(String parentCid, String childCid) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("parent_cid", parentCid);
        body.put("child_cid", childCid);
        request("DELETE", "/v1/links", body, false);
    }

    /**
     * Reports this person's links, each with the role ("parent" or "child")
     * this cid plays in it.
     */
    public List<Map<String, Object>> listLinks(String cid) {
        return listOf(request("GET", "/v1/contacts/" + encode(cid) + "/links", null, true), "links");
    }

    // -- attribute version history ---------------------------------------------------------

    /**
     * Reports the retained revisions of a person's attributes, newest first.
     *
     * <p>How many are kept is the server's {@code SUNDER_VERSIONS_KEEP} /
     * {@code _TTL} decision; history is personal data and is destroyed by
     * erasure like everything else.
     */
    public List<Map<String, Object>> listVersions(String cid) {
        return listOf(request("GET", "/v1/contacts/" + encode(cid) + "/versions", null, true), "versions");
    }

    /**
     * Reads one attribute as it was at a past revision.
     *
     * <p>Purpose-gated, consent-gated and audited exactly like a current read:
     * an old value is not a lesser secret.
     */
    public String getVersionAttribute(String cid, long versionNo, String name, String purpose) {
        String path = "/v1/contacts/" + encode(cid)
                + "/versions/" + versionNo
                + "/attributes/" + encode(name)
                + "?purpose=" + encode(purpose);
        return requireString(request("GET", path, null, true), "value");
    }

    // -- external claims ----------------------------------------------------------------------

    /**
     * Ingests a signed envelope from a trusted issuer; returns the names
     * actually stored.
     *
     * <p>Stored attribute names carry the issuer's provenance after an '@'
     * separator - which is why '@' is refused in a caller-supplied attribute
     * name: an attribute an external issuer vouched for must never be
     * impersonable by an ordinary write.
     */
    public List<String> storeExternalClaim(String cid, String envelope) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("cid", cid);
        body.put("envelope", envelope);
        return stringsOf(request("POST", "/v1/claims/external", body, false), "stored");
    }

    // -- admin ----------------------------------------------------------------------------------

    /**
     * Mints a single-use token authorizing one privileged call.
     *
     * <p>"search" covers fuzzy and partial lookups when
     * {@code SUNDER_SEARCH_UNLOCK} is on; "tokens" covers the bulk vault routes.
     * It lives about a minute and is spent by ONE call. Requires the
     * {@code admin.unlock} action, and the server refuses to grant that to a
     * credential with no expiry: a standing key to every gated surface is not
     * something an audit can reconstruct after the fact.
     */
    public Map<String, Object> unlock(String purpose) {
        return request("POST", "/v1/admin/unlock", Map.of("purpose", purpose), false);
    }

    // -- transport -------------------------------------------------------------

    /**
     * One HTTP round trip; a single extra attempt when {@code retryOnce} is
     * set and the failure is a 5xx or a network error.
     */
    private Map<String, Object> request(String method, String path,
                                        Map<String, Object> body, boolean retryOnce) {
        return request(method, path, body, retryOnce, Map.of(), null);
    }

    private Map<String, Object> request(String method, String path,
                                        Map<String, Object> body, boolean retryOnce,
                                        Map<String, String> extraHeaders, byte[] rawBody) {
        int attempts = retryOnce ? 2 : 1;
        ServiceUnavailableException lastError = null;
        for (int attempt = 0; attempt < attempts; attempt++) {
            try {
                return doRequest(method, path, body, extraHeaders, rawBody);
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

    private Map<String, Object> doRequest(String method, String path, Map<String, Object> body,
                                          Map<String, String> extraHeaders, byte[] rawBody) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Authorization", "Bearer " + credential)
                .header("Accept", "application/json");
        if (userId != null) {
            builder.header("X-Sunder-User-Id", userId);
        }
        for (Map.Entry<String, String> h : extraHeaders.entrySet()) {
            builder.header(h.getKey(), h.getValue());
        }
        if (rawBody != null) {
            // Pre-encoded body (a multipart upload); the caller supplied the
            // Content-Type with its boundary in extraHeaders.
            builder.method(method, HttpRequest.BodyPublishers.ofByteArray(rawBody));
        } else if (body != null) {
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

    /** Pulls a list of objects out of a parsed response body, or an empty list. */
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> listOf(Map<String, Object> map, String key) {
        Object value = map.get(key);
        List<Map<String, Object>> out = new ArrayList<>();
        if (value instanceof List<?> items) {
            for (Object item : items) {
                if (item instanceof Map<?, ?> m) {
                    out.add((Map<String, Object>) m);
                }
            }
        }
        return out;
    }

    /** Pulls a list of strings out of a parsed response body, or an empty list. */
    private static List<String> stringsOf(Map<String, Object> map, String key) {
        Object value = map.get(key);
        List<String> out = new ArrayList<>();
        if (value instanceof List<?> items) {
            for (Object item : items) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }

    /** Percent-encodes one path segment or query value (RFC 3986, nothing safe). */
    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
