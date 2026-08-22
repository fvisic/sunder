/**
 * Sunder TypeScript SDK — a thin client for the Sunder pseudonymous
 * identity provider (v1 API).
 *
 * Design rules (PLAN section 10):
 * - Zero cryptography here: transport, auth, timeouts, retries, error mapping.
 * - Zero runtime dependencies: global fetch (Node 18+ / browsers).
 * - Per-endpoint retry policy: lookup* and issueOti retry once on 5xx or
 *   network failure; verifyOti is NEVER blind-retried (single-use token —
 *   a retry after an ambiguous network failure would legitimately return
 *   TokenUsed; that outcome is surfaced distinctly for the caller to decide).
 */

/** Unified error taxonomy, identical across all Sunder SDKs. */
export type SunderErrorCode =
  | "Unauthorized"
  | "Forbidden"
  | "PurposeNotAllowed"
  | "AudienceMismatch"
  | "NotFound"
  | "Ambiguous"
  | "Validation"
  | "TokenInvalid"
  | "TokenUsed"
  | "TokenExpired"
  | "RateLimited"
  | "ServiceUnavailable"
  | "NetworkError"
  | "Unknown";

/** Error thrown by every SunderClient method on a non-success outcome. */
export class SunderError extends Error {
  /** Taxonomy code — stable across SDK languages. */
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
function mapError(status: number, serverError: string | undefined): SunderErrorCode {
  if (status >= 500) return "ServiceUnavailable";
  switch (status) {
    case 400:
      return serverError === "token_invalid" ? "TokenInvalid" : "Validation";
    case 401:
      return "Unauthorized";
    case 403:
      if (serverError === "purpose_not_allowed") return "PurposeNotAllowed";
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

/** Input for registerContact. At least one of email/phone is required. */
export interface ContactAttributes {
  email?: string;
  phone?: string;
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

/** Second factor for lookupByName — a name alone is never an identifier. */
export interface SecondFactor {
  email?: string;
  phone?: string;
}

export interface CidResult {
  cid: string;
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
 * interface (PLAN section 10.1). All methods throw SunderError on failure.
 *
 * Remember: LOOKUP != AUTHENTICATION — a lookup hit never proves the caller
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
   * Issues the same person's CID in another scope. Linkage-capable —
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
   * Finds a contact by name plus a second factor (email or phone) — a name
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
    options?: RequestOptions,
  ): Promise<OtiResult> {
    const raw = await this.request<{ token: string; expires_at: string }>({
      method: "POST",
      path: "/v1/oti",
      body: { cid, purpose, audience },
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
  ): Promise<CidResult> {
    return this.request<CidResult>({
      method: "POST",
      path: "/v1/oti/verify",
      body: { token, purpose, audience },
      retryOnce: false, // single-use token — see method doc
      options,
    });
  }

  // -- ops -------------------------------------------------------------------

  /** Liveness check (unauthenticated GET /healthz). */
  async health(options?: RequestOptions): Promise<HealthResult> {
    const res = await this.fetchOnce("GET", "/healthz", undefined, options);
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
          "NetworkError",
          `network failure calling ${call.method} ${call.path}: ${String(err)}`,
          0,
        );
        continue; // retryable if attempts remain
      }
      if (res.ok) {
        return (await res.json()) as T;
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
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.credential}`,
      Accept: "application/json",
    };
    const init: RequestInit = {
      method,
      headers,
      signal: AbortSignal.any(signals),
    };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    return fetch(`${this.url}${path}`, init);
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
