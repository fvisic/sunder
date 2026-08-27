/**
 * Sunder TypeScript SDK - a thin client for the Sunder pseudonymous
 * identity provider (v1 API).
 *
 * Design rules (docs/DESIGN.md, SDK design rules):
 * - Zero cryptography here: transport, auth, timeouts, retries, error mapping.
 * - Zero runtime dependencies: global fetch (Node 18+ / browsers).
 * - Per-endpoint retry policy: lookup* and issueOti retry once on 5xx or
 *   network failure; verifyOti is NEVER blind-retried (single-use token -
 *   a retry after an ambiguous network failure would legitimately return
 *   TokenUsed; that outcome is surfaced distinctly for the caller to decide).
 */

/** Unified error taxonomy, identical across all Sunder SDKs. */
export type SunderErrorCode =
  | "Unauthorized"
  | "Forbidden"
  | "PurposeNotAllowed"
  // The credential IS entitled, but the call needs a single-use unlock
  // token it did not present (POST /v1/admin/unlock, then X-Sunder-Unlock).
  // Distinct from Forbidden: the two call for opposite responses.
  | "UnlockRequired"
  | "AudienceMismatch"
  | "NotFound"
  | "Validation"
  | "TokenInvalid"
  | "TokenUsed"
  | "TokenExpired"
  | "RateLimited"
  // Also raised (status 0) on network-level failures - identical taxonomy
  // and trigger conditions across all Sunder SDKs.
  | "ServiceUnavailable"
  // A 2xx whose body is not the expected JSON shape - same code the other
  // four SDKs use ("bad_response").
  | "BadResponse"
  // The data subject withdrew consent for this purpose - distinct from
  // PurposeNotAllowed (a missing client grant).
  | "ConsentDenied"
  // The secret is correct but past its expiry: rotate it, do not retry.
  | "CredentialExpired"
  | "Unknown";

/**
 * Manual composition of abort signals for runtimes without
 * AbortSignal.any. Returns a cleanup function: listeners on a
 * caller-supplied long-lived signal MUST be removed on completion, or they
 * accumulate per request (review finding F17).
 */
function combineSignals(signals: AbortSignal[]): { signal: AbortSignal; cleanup: () => void } {
  const controller = new AbortController();
  const added: Array<[AbortSignal, () => void]> = [];
  for (const s of signals) {
    if (s.aborted) {
      controller.abort(s.reason);
      break;
    }
    const onAbort = () => controller.abort(s.reason);
    s.addEventListener("abort", onAbort, { once: true });
    added.push([s, onAbort]);
  }
  return {
    signal: controller.signal,
    cleanup: () => {
      for (const [s, fn] of added) s.removeEventListener("abort", fn);
    },
  };
}

/** Error thrown by every SunderClient method on a non-success outcome. */
export class SunderError extends Error {
  /** Taxonomy code - stable across SDK languages. */
  readonly code: SunderErrorCode;
  /** HTTP status of the response, or 0 for network-level failures. */
  readonly status: number;
  /** Raw `error` field from the server's JSON body, if any. */
  readonly serverError?: string;
  /** Optional `detail` field from the server's JSON body. */
  readonly detail?: string;

  constructor(
    code: SunderErrorCode,
    message: string,
    status: number,
    serverError?: string,
    detail?: string,
  ) {
    super(message);
    this.name = "SunderError";
    this.code = code;
    this.status = status;
    this.serverError = serverError;
    this.detail = detail;
  }
}

/** Maps an HTTP status plus the server's JSON `error` field to the taxonomy. */
// Code-first, then status - the same order the python/php/java/dotnet SDKs
// use, so a server code maps identically everywhere (review finding F15).
const CODE_MAP: Record<string, SunderErrorCode> = {
  unauthorized: "Unauthorized",
  credential_expired: "CredentialExpired",
  forbidden: "Forbidden",
  consent_denied: "ConsentDenied",
  purpose_not_allowed: "PurposeNotAllowed",
  unlock_required: "UnlockRequired",
  audience_mismatch: "AudienceMismatch",
  not_found: "NotFound",
  validation: "Validation",
  bad_json: "Validation",
  token_invalid: "TokenInvalid",
  token_used: "TokenUsed",
  token_expired: "TokenExpired",
  rate_limited: "RateLimited",
  service_unavailable: "ServiceUnavailable",
  bad_response: "BadResponse",
};

function mapError(status: number, serverError: string | undefined): SunderErrorCode {
  if (serverError && CODE_MAP[serverError]) return CODE_MAP[serverError];
  if (status >= 500) return "ServiceUnavailable";
  switch (status) {
    case 400:
      return serverError === "token_invalid" ? "TokenInvalid" : "Validation";
    case 401:
      return "Unauthorized";
    case 403:
      if (serverError === "purpose_not_allowed") return "PurposeNotAllowed";
      if (serverError === "unlock_required") return "UnlockRequired";
      if (serverError === "audience_mismatch") return "AudienceMismatch";
      return "Forbidden";
    case 404:
      return "NotFound";
    case 409:
      return "TokenUsed";
    case 410:
      return "TokenExpired";
    case 429:
      return "RateLimited";
    default:
      return "Unknown";
  }
}

/** Input for registerContact. At least one email or phone is required. */
export interface ContactAttributes {
  /** Primary email (searchable). */
  email?: string;
  /** Additional searchable emails. */
  emails?: string[];
  /** Primary phone (searchable, E.164 or common formatting). */
  phone?: string;
  /** Additional searchable phones. */
  phones?: string[];
  name?: string;
  /**
   * Additional attributes stored in the caller-scope encrypted blob.
   * `email`, `phone` and `name` are reserved names and rejected here.
   */
  attributes?: Record<string, string>;
}

/** Per-call options. */
export interface RequestOptions {
  /** Abort signal for this call (combined with the client timeout). */
  signal?: AbortSignal;
}

/** Second factor for lookupByName - a name alone is never an identifier. */
export interface SecondFactor {
  email?: string;
  phone?: string;
}

export interface CidResult {
  cid: string;
}

/** One issuer-authorized predicate claim (P2.3 selective disclosure). */
export interface SharePredicate {
  attr: string;
  /** "age_gte" (attr read as an ISO date) or "exists". */
  op: "age_gte" | "exists";
  /**
   * Required for "age_gte" - an omitted threshold is rejected at issue
   * time, never treated as 0. Must be absent for "exists".
   */
  value?: number;
}

/** An evaluated predicate: booleans only, the value never crosses scopes. */
export interface PredicateResult extends SharePredicate {
  result: boolean;
  /**
   * Op-specific. For "age_gte": false when the attribute is absent or
   * unparseable, so "we do not know the birthdate" never reads as "under
   * 18". For "exists": always true - absence is the answer that predicate
   * asks for.
   */
  known: boolean;
}

export interface VerifyResult {
  cid: string;
  /** Attribute names copied into the verifier scope, when requested. */
  shared?: string[];
  /** Evaluated predicate claims, when the token carried any. */
  predicates?: PredicateResult[];
}

export interface AttributeResult {
  value: string;
}

export interface OtiResult {
  token: string;
  /** RFC 3339 timestamp; tokens live 5 minutes, one use, one audience, one purpose. */
  expiresAt: string;
}

export interface HealthResult {
  status: string;
}

/** Constructor options; each falls back to its environment variable. */
export interface SunderClientOptions {
  /** Base URL of the Sunder instance. Default: env SUNDER_URL. */
  url?: string;
  /** `<client_id>.<secret>` bearer credential. Default: env SUNDER_CREDENTIAL. */
  credential?: string;
  /** Per-request timeout in milliseconds. Default: 10000. */
  timeoutMs?: number;
}

interface Call {
  method: "GET" | "POST";
  path: string;
  body?: unknown;
  /** Retry once on 5xx / network failure. NEVER set for verifyOti. */
  retryOnce?: boolean;
  options?: RequestOptions;
}

function readEnv(name: string): string | undefined {
  // globalThis.process keeps the file loadable outside Node without @types tricks.
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } })
    .process?.env;
  return env?.[name];
}

/**
 * Client for the Sunder v1 API. Implements the canonical CidProviderClient
 * interface (docs/DESIGN.md, SDK design rules). All methods throw SunderError on failure.
 *
 * Remember: LOOKUP != AUTHENTICATION - a lookup hit never proves the caller
 * is talking to that person.
 */
export class SunderClient {
  private readonly url: string;
  private readonly credential: string;
  private readonly timeoutMs: number;

  constructor(options: SunderClientOptions = {}) {
    const url = options.url ?? readEnv("SUNDER_URL");
    const credential = options.credential ?? readEnv("SUNDER_CREDENTIAL");
    if (!url) {
      throw new SunderError(
        "Validation",
        "missing Sunder URL: pass { url } or set SUNDER_URL",
        0,
      );
    }
    if (!credential) {
      throw new SunderError(
        "Validation",
        "missing credential: pass { credential } or set SUNDER_CREDENTIAL",
        0,
      );
    }
    this.url = url.replace(/\/+$/, "");
    this.credential = credential;
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  // -- contacts ------------------------------------------------------------

  /** Registers (or dedup-merges) a contact. Returns the caller-scope CID. */
  async registerContact(
    attributes: ContactAttributes,
    options?: RequestOptions,
  ): Promise<CidResult> {
    return this.request<CidResult>({
      method: "POST",
      path: "/v1/contacts",
      body: attributes,
      options,
    });
  }

  /**
   * Issues the same person's CID in another scope. Linkage-capable -
   * grant sparingly; prefer OTIs for cross-system handoff.
   */
  async issueScopedCid(
    cid: string,
    scope: string,
    options?: RequestOptions,
  ): Promise<CidResult> {
    return this.request<CidResult>({
      method: "POST",
      path: `/v1/contacts/${encodeURIComponent(cid)}/scopes`,
      body: { scope },
      options,
    });
  }

  // -- lookup (LOOKUP != AUTHENTICATION) -------------------------------------

  /** Finds a contact by email. Throws NotFound on a miss. Retries once on 5xx. */
  async lookupByEmail(email: string, options?: RequestOptions): Promise<CidResult> {
    return this.request<CidResult>({
      method: "POST",
      path: "/v1/lookup",
      body: { email },
      retryOnce: true,
      options,
    });
  }

  /** Finds a contact by phone. Throws NotFound on a miss. Retries once on 5xx. */
  async lookupByPhone(phone: string, options?: RequestOptions): Promise<CidResult> {
    return this.request<CidResult>({
      method: "POST",
      path: "/v1/lookup",
      body: { phone },
      retryOnce: true,
      options,
    });
  }

  /**
   * Finds a contact by name plus a second factor (email or phone) - a name
   * alone is a narrowing key, never an identifier, and is rejected server-side.
   */
  async lookupByName(
    name: string,
    secondFactor: SecondFactor,
    options?: RequestOptions,
  ): Promise<CidResult> {
    const body: Record<string, string> = { name };
    if (secondFactor.email !== undefined) body.email = secondFactor.email;
    if (secondFactor.phone !== undefined) body.phone = secondFactor.phone;
    return this.request<CidResult>({
      method: "POST",
      path: "/v1/lookup",
      body,
      retryOnce: true,
      options,
    });
  }

  // -- attributes ------------------------------------------------------------

  /**
   * Fetches exactly one attribute; `purpose` is mandatory and must be in the
   * caller's allowed purposes. Every fetch is audited server-side.
   */
  async getAttribute(
    cid: string,
    name: string,
    purpose: string,
    options?: RequestOptions,
  ): Promise<AttributeResult> {
    const path =
      `/v1/contacts/${encodeURIComponent(cid)}/attributes/${encodeURIComponent(name)}` +
      `?purpose=${encodeURIComponent(purpose)}`;
    return this.request<AttributeResult>({ method: "GET", path, options });
  }

  // -- OTI ---------------------------------------------------------------

  /**
   * Issues a one-time identifier: 5 minutes, one use, one audience, one
   * purpose. Safe to retry (retries once on 5xx / network failure).
   */
  async issueOti(
    cid: string,
    purpose: string,
    audience: string,
    options?: RequestOptions & {
      /** Issuer-authorized attributes copied into the verifier's scope. */
      shareAttributes?: string[];
      /** Issuer-authorized predicate claims (evaluated at verification). */
      sharePredicates?: SharePredicate[];
    },
  ): Promise<OtiResult> {
    const raw = await this.request<{ token: string; expires_at: string }>({
      method: "POST",
      path: "/v1/oti",
      body: {
        cid,
        purpose,
        audience,
        ...(options?.shareAttributes ? { share_attributes: options.shareAttributes } : {}),
        ...(options?.sharePredicates ? { share_predicates: options.sharePredicates } : {}),
      },
      retryOnce: true,
      options,
    });
    return { token: raw.token, expiresAt: raw.expires_at };
  }

  /**
   * Verifies and consumes a one-time identifier; returns the VERIFIER's own
   * scoped CID. NEVER blind-retried: the token is single-use, so a retry
   * after an ambiguous network failure would legitimately return TokenUsed.
   * On TokenUsed after a failure, the caller decides how to reconcile.
   */
  async verifyOti(
    token: string,
    purpose: string,
    audience: string,
    options?: RequestOptions,
  ): Promise<VerifyResult> {
    return this.request<VerifyResult>({
      method: "POST",
      path: "/v1/oti/verify",
      body: { token, purpose, audience },
      retryOnce: false, // single-use token - see method doc
      options,
    });
  }

  // -- ops -------------------------------------------------------------------

  /** Liveness check (unauthenticated GET /healthz). */
  async health(options?: RequestOptions): Promise<HealthResult> {
    let res: Response;
    try {
      res = await this.fetchOnce("GET", "/healthz", undefined, options);
    } catch (err) {
      // Same contract as every other method: network failures surface as
      // SunderError, never as raw fetch exceptions.
      throw new SunderError(
        "ServiceUnavailable",
        `network failure calling GET /healthz: ${String(err)}`,
        0,
      );
    }
    const text = await res.text();
    if (!res.ok) {
      throw new SunderError(
        mapError(res.status, undefined),
        `health check failed: HTTP ${res.status}`,
        res.status,
      );
    }
    return { status: text.trim() || "ok" };
  }

  // -- transport -------------------------------------------------------------

  private async request<T>(call: Call): Promise<T> {
    const attempts = call.retryOnce ? 2 : 1;
    let lastError: SunderError | undefined;
    for (let attempt = 1; attempt <= attempts; attempt++) {
      let res: Response;
      try {
        res = await this.fetchOnce(call.method, call.path, call.body, call.options);
      } catch (err) {
        lastError = new SunderError(
          "ServiceUnavailable",
          `network failure calling ${call.method} ${call.path}: ${String(err)}`,
          0,
        );
        continue; // retryable if attempts remain
      }
      if (res.ok) {
        // A non-JSON success body must surface as SunderError, never as a
        // raw SyntaxError (review finding F14).
        try {
          return (await res.json()) as T;
        } catch (err) {
          throw new SunderError(
            "BadResponse",
            `${call.method} ${call.path} returned a non-JSON success body: ${String(err)}`,
            res.status,
            "bad_response",
          );
        }
      }
      const parsed = await parseErrorBody(res);
      const code = mapError(res.status, parsed.error);
      lastError = new SunderError(
        code,
        `${call.method} ${call.path} failed: ${code} (HTTP ${res.status}` +
          (parsed.error ? `, ${parsed.error}` : "") +
          `)`,
        res.status,
        parsed.error,
        parsed.detail,
      );
      if (code !== "ServiceUnavailable") {
        throw lastError; // only 5xx is retryable
      }
    }
    throw lastError!;
  }

  private async fetchOnce(
    method: string,
    path: string,
    body: unknown,
    options?: RequestOptions,
  ): Promise<Response> {
    const signals: AbortSignal[] = [AbortSignal.timeout(this.timeoutMs)];
    if (options?.signal) signals.push(options.signal);
    // AbortSignal.any() only exists since Node 20.3; compose manually below
    // it so the documented Node 18+ support actually holds.
    let combined: AbortSignal;
    let cleanup = () => {};
    if (signals.length === 1) {
      combined = signals[0]!;
    } else if (typeof AbortSignal.any === "function") {
      combined = AbortSignal.any(signals);
    } else {
      const composed = combineSignals(signals);
      combined = composed.signal;
      cleanup = composed.cleanup;
    }
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.credential}`,
      Accept: "application/json",
    };
    const init: RequestInit = {
      method,
      headers,
      signal: combined,
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    try {
      return await fetch(`${this.url}${path}`, init);
    } finally {
      // Drop listeners on the caller's long-lived signal (finding F17).
      cleanup();
    }
  }
}

async function parseErrorBody(
  res: Response,
): Promise<{ error?: string; detail?: string }> {
  try {
    const data = (await res.json()) as { error?: unknown; detail?: unknown };
    return {
      error: typeof data.error === "string" ? data.error : undefined,
      detail: typeof data.detail === "string" ? data.detail : undefined,
    };
  } catch {
    return {};
  }
}

export default SunderClient;
