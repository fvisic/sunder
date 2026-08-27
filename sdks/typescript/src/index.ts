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

/** One purpose's consent state for a person. */
export interface Consent {
  purpose: string;
  granted: boolean;
  updated_at?: string;
}

/** One tokenized value held for a person - never the value itself. */
export interface ValueTokenRef {
  token: string;
  type?: string;
  scope?: string;
  created_by?: string;
  created_at?: string;
  last_used?: string;
  expires_at?: string;
}

/** One cross-org share seen from the discloser's side: who received what. */
export interface ShareRef {
  uuid: string;
  partner_label?: string;
  purpose?: string;
  fields?: string[];
  created_at?: string;
  expires_at?: string;
  revoked?: boolean;
}

/** One person link as seen from this cid. */
export interface LinkRef {
  cid: string;
  link_type: string;
  /** "parent" or "child" - which side this cid is on. */
  role?: string;
}

/** Metadata for one stored file. `sha256` digests the PLAINTEXT. */
export interface FileMeta {
  id: string;
  name?: string;
  content_type?: string;
  size_bytes?: number;
  sha256?: string;
  created_at?: string;
  expires_at?: string;
}

/** One scope's complete holdings for a person (DSR responses). */
export interface ScopeData {
  scope: string;
  cid: string;
  attributes?: Record<string, string>;
  consents?: Consent[];
  value_tokens?: ValueTokenRef[];
  files?: FileMeta[];
  shares?: ShareRef[];
  links?: LinkRef[];
}

/**
 * One row of the Article 15 access trail. Under bucketed read auditing a
 * read entry carries `count` and `last_ts` for its hour rather than one row
 * per event.
 */
export interface AuditEntry {
  seq?: number;
  ts: string;
  client_id: string;
  user_id?: string;
  action: string;
  cid?: string;
  count?: number;
  last_ts?: string;
}

/** Article 15 answer: every scope's holdings plus who accessed them. */
export interface AccessResult {
  scopes: ScopeData[];
  audit_trail?: AuditEntry[];
}

/** One linked child and whether the erasure reached it. */
export interface LinkedErasure {
  cid: string;
  link_type: string;
  cascaded: boolean;
}

export interface EraseResult {
  erasure_id: number;
  scopes: number;
  linked?: LinkedErasure[];
}

/** One value to vault. The value is encrypted at rest; the token is opaque. */
export interface TokenizeInput {
  value: string;
  /** "string" (default) or "card", which also validates the Luhn checksum. */
  type?: "string" | "card";
  /**
   * Binds the token to a person in the caller's scope, so erasure and the
   * retention sweep destroy it. Omit ONLY for a scope-wide value belonging
   * to no single subject: an unattributed token survives that erasure.
   */
  cid?: string;
  /** Dedup per (scope, cid): the same value returns the same token. */
  unique?: boolean;
  /** Hard deadline, decided by the DATABASE clock. */
  expires_final?: string;
  /** Life extension on every read; 0 = none. */
  sliding_seconds?: number;
}

export interface ShareInput {
  cid: string;
  /** A share is a SNAPSHOT - later attribute changes do not propagate. */
  fields: string[];
  /** Identifies the recipient in the audit trail and Article 15 answer. */
  partner_label?: string;
  purpose?: string;
  ttl_seconds?: number;
}

export interface ShareResult {
  uuid: string;
  expires_at?: string;
}

/** One retained revision of a person's attribute blob. */
export interface BlobVersion {
  version_no: number;
  written_by?: string;
  written_at?: string;
}

/** A short-lived single-use token authorizing one privileged call. */
export interface UnlockResult {
  unlock_token: string;
  expires_at?: string;
}

/** Constructor options; each falls back to its environment variable. */
export interface SunderClientOptions {
  /** Base URL of the Sunder instance. Default: env SUNDER_URL. */
  url?: string;
  /** `<client_id>.<secret>` bearer credential. Default: env SUNDER_CREDENTIAL. */
  credential?: string;
  /** Per-request timeout in milliseconds. Default: 10000. */
  timeoutMs?: number;
  /**
   * Attributes every read to an operator inside the calling system, sent as
   * `X-Sunder-User-Id` and recorded in the audit chain. It upgrades an
   * Article 15 answer from "which system accessed this" to "which operator
   * that system says accessed it".
   *
   * CLIENT-ASSERTED and unverifiable by design: Sunder records the claim and
   * proves it was not altered afterwards, not that it was true. Accepts
   * [A-Za-z0-9._@:-], 1-64 characters; anything else is a 400 rather than a
   * silent drop.
   */
  userId?: string;
}

interface Call {
  method: "GET" | "POST" | "DELETE";
  path: string;
  body?: unknown;
  /** Retry once on 5xx / network failure. NEVER set for verifyOti. */
  retryOnce?: boolean;
  options?: RequestOptions;
  /** Call-specific headers - the unlock token, a file expiry deadline. */
  headers?: Record<string, string>;
  /** Pre-encoded body (multipart upload); bypasses JSON encoding. */
  rawBody?: BodyInit;
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
  private readonly userId?: string;

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
    this.userId = options.userId;
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


  // -- consent ---------------------------------------------------------------

  /**
   * Records the person's decision for one purpose. Consent gates attribute
   * reads for that purpose: revoking it makes getAttribute throw
   * ConsentDenied even though the client's own grant is unchanged.
   *
   * Every call is appended to the audit chain, and that trail SURVIVES
   * erasure - it is the accountability record of what was consented to.
   */
  async setConsent(
    cid: string,
    purpose: string,
    granted: boolean,
    options?: RequestOptions,
  ): Promise<Consent> {
    return this.request<Consent>({
      method: "POST",
      path: "/v1/consent",
      body: { cid, purpose, granted },
      options,
    });
  }

  /**
   * Lists every purpose the caller's scope has recorded for this person. A
   * purpose that was never set is ABSENT, not false: "no decision" and
   * "refused" are different facts.
   */
  async getConsent(cid: string, options?: RequestOptions): Promise<Consent[]> {
    const raw = await this.request<{ consents?: Consent[] }>({
      method: "GET",
      path: `/v1/consent/${encodeURIComponent(cid)}`,
      retryOnce: true,
      options,
    });
    return raw.consents ?? [];
  }

  // -- data subject rights ---------------------------------------------------

  /**
   * Article 15, ORG-WIDE: it crosses scope boundaries on the data subject's
   * behalf, so it needs its own grant and is itself audited. Never route it
   * through an ordinary integration credential.
   */
  async dsrAccess(cid: string, options?: RequestOptions): Promise<AccessResult> {
    return this.request<AccessResult>({
      method: "GET",
      path: `/v1/dsr/access?cid=${encodeURIComponent(cid)}`,
      retryOnce: true,
      options,
    });
  }

  /** Article 20 for the CALLER's scope only: the same holdings, portable. */
  async dsrExport(cid: string, options?: RequestOptions): Promise<ScopeData> {
    return this.request<ScopeData>({
      method: "GET",
      path: `/v1/dsr/export?cid=${encodeURIComponent(cid)}`,
      retryOnce: true,
      options,
    });
  }

  /**
   * Article 17: erases the person org-wide and queues one Article 19
   * notification per scope that held them.
   *
   * `cascade` names the link types ("guardian", "member", "owner") whose
   * children are erased too. Omitted, the children are LISTED in the result
   * and left untouched - an accidental cascade would delete a third party's
   * data, so it is opt-in per link type.
   *
   * A cascade is one transaction PER PERSON, and the plan is recorded before
   * any child is touched: re-issuing the identical call after an
   * interruption RESUMES the outstanding children. Once everything is done
   * it throws NotFound, deliberately indistinguishable from a cid that never
   * existed.
   *
   * NEVER retried: it is destructive, and resuming is the caller's decision.
   */
  async dsrErase(
    cid: string,
    cascade?: string[],
    options?: RequestOptions,
  ): Promise<EraseResult> {
    return this.request<EraseResult>({
      method: "POST",
      path: "/v1/dsr/erase",
      // An empty array must not be sent: absence is what "cascade nothing"
      // looks like on the wire.
      body: { cid, ...(cascade && cascade.length > 0 ? { cascade } : {}) },
      options,
    });
  }

  // -- value tokenization ----------------------------------------------------

  /** Vaults one value and returns its opaque token. */
  async tokenize(input: TokenizeInput, options?: RequestOptions): Promise<string> {
    const raw = await this.request<{ token: string }>({
      method: "POST",
      path: "/v1/tokens",
      body: input,
      options,
    });
    return raw.token;
  }

  /**
   * Resolves a token back to its value. Audited per read and, for a
   * cid-bound token, attributed to that person's CID - so "who read my
   * tokenized IBAN" is answerable from the access trail.
   */
  async detokenize(token: string, options?: RequestOptions): Promise<string> {
    const raw = await this.request<{ value: string }>({
      method: "GET",
      path: `/v1/tokens/${encodeURIComponent(token)}`,
      retryOnce: true,
      options,
    });
    return raw.value;
  }

  /** Destroys a token and its value. Not retried: it is destructive. */
  async deleteToken(token: string, options?: RequestOptions): Promise<void> {
    await this.request<unknown>({
      method: "DELETE",
      path: `/v1/tokens/${encodeURIComponent(token)}`,
      options,
    });
  }

  /**
   * Vaults many values in one call; tokens come back in input order.
   *
   * Bulk surfaces ALWAYS require a single-use unlock token, regardless of
   * SUNDER_SEARCH_UNLOCK: one call touching many people is exactly the shape
   * a rate limit does not constrain. Get one from `unlock("tokens")`. The
   * whole batch is validated before the token is spent, so a rejected item
   * does not burn the unlock.
   */
  async tokenizeBulk(
    unlockToken: string,
    items: TokenizeInput[],
    options?: RequestOptions,
  ): Promise<string[]> {
    const raw = await this.request<{ tokens?: string[] }>({
      method: "POST",
      path: "/v1/tokens/bulk",
      body: { items },
      headers: { "X-Sunder-Unlock": unlockToken },
      options,
    });
    return raw.tokens ?? [];
  }

  /** Resolves many tokens in one call. Requires an unlock token. */
  async detokenizeBulk(
    unlockToken: string,
    tokens: string[],
    options?: RequestOptions,
  ): Promise<string[]> {
    const raw = await this.request<{ values?: string[] }>({
      method: "POST",
      path: "/v1/tokens/bulk/read",
      body: { tokens },
      headers: { "X-Sunder-Unlock": unlockToken },
      options,
    });
    return raw.values ?? [];
  }

  // -- file vault ------------------------------------------------------------

  /**
   * Stores a file for a person. Each file gets its own data key, wrapped by
   * the person's record key - so erasing the person shreds the file even if
   * the object store still holds the ciphertext.
   *
   * `expiresAt` (RFC 3339) sets a hard deadline after which the file is
   * unreadable and collected by the retention sweep.
   *
   * Never retried: a retried upload after an ambiguous failure stores twice.
   */
  async uploadFile(
    cid: string,
    file: Blob,
    filename: string,
    expiresAt?: string,
    options?: RequestOptions,
  ): Promise<FileMeta> {
    const form = new FormData();
    form.append("file", file, filename);
    return this.request<FileMeta>({
      method: "POST",
      path: `/v1/contacts/${encodeURIComponent(cid)}/files`,
      rawBody: form,
      ...(expiresAt ? { headers: { "X-Sunder-File-Expiry": expiresAt } } : {}),
      options,
    });
  }

  /**
   * Lists a person's files (metadata only). Purpose-gated and consent-gated
   * like any other read; expired files are hidden.
   */
  async listFiles(
    cid: string,
    purpose: string,
    options?: RequestOptions,
  ): Promise<FileMeta[]> {
    const raw = await this.request<{ files?: FileMeta[] }>({
      method: "GET",
      path: `/v1/contacts/${encodeURIComponent(cid)}/files?purpose=${encodeURIComponent(purpose)}`,
      retryOnce: true,
      options,
    });
    return raw.files ?? [];
  }

  /**
   * Downloads one file's plaintext.
   *
   * A download that fails mid-stream ABORTS the connection rather than
   * completing a 200 with a short body, so a truncated read surfaces as a
   * transport error - verify the length, or the `sha256` from listFiles,
   * before treating the bytes as complete.
   */
  async downloadFile(
    id: string,
    purpose: string,
    options?: RequestOptions,
  ): Promise<Blob> {
    const path = `/v1/files/${encodeURIComponent(id)}?purpose=${encodeURIComponent(purpose)}`;
    let res: Response;
    try {
      res = await this.fetchOnce("GET", path, undefined, options);
    } catch (err) {
      throw new SunderError(
        "ServiceUnavailable",
        `network failure calling GET ${path}: ${String(err)}`,
        0,
      );
    }
    if (!res.ok) {
      // A 404 must not reach the caller as a Blob over an error page.
      const parsed = await parseErrorBody(res);
      const code = mapError(res.status, parsed.error);
      throw new SunderError(
        code,
        `GET ${path} failed: ${code} (HTTP ${res.status})`,
        res.status,
        parsed.error,
        parsed.detail,
      );
    }
    return res.blob();
  }

  /**
   * Removes a file. Its name and digest are redacted immediately; the
   * ciphertext is collected by the retention sweep. Not retried.
   */
  async deleteFile(id: string, options?: RequestOptions): Promise<void> {
    await this.request<unknown>({
      method: "DELETE",
      path: `/v1/files/${encodeURIComponent(id)}`,
      options,
    });
  }

  // -- cross-org shares ------------------------------------------------------

  /**
   * Discloses a snapshot of named fields to a partner. The returned uuid is
   * unguessable and, when the server runs with SUNDER_SHARES_PUBLIC, is the
   * ONLY credential needed to fetch it - treat it as a bearer secret.
   */
  async createShare(input: ShareInput, options?: RequestOptions): Promise<ShareResult> {
    return this.request<ShareResult>({
      method: "POST",
      path: "/v1/shares",
      body: input,
      options,
    });
  }

  /**
   * Reads a share's fields. Whether this needs a credential is the server's
   * SUNDER_SHARES_PUBLIC decision; the SDK sends one either way. An expired,
   * revoked or erased share throws NotFound.
   */
  async fetchShare(
    uuid: string,
    options?: RequestOptions,
  ): Promise<Record<string, string>> {
    const raw = await this.request<{ fields?: Record<string, string> }>({
      method: "GET",
      path: `/v1/shares/${encodeURIComponent(uuid)}`,
      retryOnce: true,
      options,
    });
    return raw.fields ?? {};
  }

  /**
   * Withdraws a share. Precise to (cid, purpose) on the consent path, so
   * revoking one never silently withdraws another. Not retried.
   */
  async revokeShare(uuid: string, options?: RequestOptions): Promise<void> {
    await this.request<unknown>({
      method: "DELETE",
      path: `/v1/shares/${encodeURIComponent(uuid)}`,
      options,
    });
  }

  // -- person links ----------------------------------------------------------

  /**
   * Relates two people in the caller's scope. Erasing the parent LISTS the
   * children; it never erases them unless dsrErase names the link type.
   */
  async link(
    parentCid: string,
    childCid: string,
    linkType: string,
    options?: RequestOptions,
  ): Promise<void> {
    await this.request<unknown>({
      method: "POST",
      path: "/v1/links",
      body: { parent_cid: parentCid, child_cid: childCid, link_type: linkType },
      options,
    });
  }

  /** Removes the relation. Not retried. */
  async unlink(
    parentCid: string,
    childCid: string,
    options?: RequestOptions,
  ): Promise<void> {
    await this.request<unknown>({
      method: "DELETE",
      path: "/v1/links",
      body: { parent_cid: parentCid, child_cid: childCid },
      options,
    });
  }

  /** Reports this person's links, each with the role this cid plays in it. */
  async listLinks(cid: string, options?: RequestOptions): Promise<LinkRef[]> {
    const raw = await this.request<{ links?: LinkRef[] }>({
      method: "GET",
      path: `/v1/contacts/${encodeURIComponent(cid)}/links`,
      retryOnce: true,
      options,
    });
    return raw.links ?? [];
  }

  // -- attribute version history ---------------------------------------------

  /**
   * Reports the retained revisions of a person's attributes, newest first.
   * How many are kept is the server's SUNDER_VERSIONS_KEEP / _TTL decision;
   * history is personal data and is destroyed by erasure like everything else.
   */
  async listVersions(cid: string, options?: RequestOptions): Promise<BlobVersion[]> {
    const raw = await this.request<{ versions?: BlobVersion[] }>({
      method: "GET",
      path: `/v1/contacts/${encodeURIComponent(cid)}/versions`,
      retryOnce: true,
      options,
    });
    return raw.versions ?? [];
  }

  /**
   * Reads one attribute as it was at a past revision. Purpose-gated,
   * consent-gated and audited exactly like a current read: an old value is
   * not a lesser secret.
   */
  async getVersionAttribute(
    cid: string,
    versionNo: number,
    name: string,
    purpose: string,
    options?: RequestOptions,
  ): Promise<string> {
    const raw = await this.request<AttributeResult>({
      method: "GET",
      path:
        `/v1/contacts/${encodeURIComponent(cid)}/versions/${encodeURIComponent(String(versionNo))}` +
        `/attributes/${encodeURIComponent(name)}?purpose=${encodeURIComponent(purpose)}`,
      retryOnce: true,
      options,
    });
    return raw.value;
  }

  // -- external claims -------------------------------------------------------

  /**
   * Ingests a signed envelope from a trusted issuer. Stored attribute names
   * carry the issuer's provenance after an '@' separator - which is why '@'
   * is refused in a caller-supplied attribute name: an attribute an external
   * issuer vouched for must never be impersonable by an ordinary write.
   */
  async storeExternalClaim(
    cid: string,
    envelope: string,
    options?: RequestOptions,
  ): Promise<string[]> {
    const raw = await this.request<{ stored?: string[] }>({
      method: "POST",
      path: "/v1/claims/external",
      body: { cid, envelope },
      options,
    });
    return raw.stored ?? [];
  }

  // -- admin -----------------------------------------------------------------

  /**
   * Mints a single-use token authorizing one privileged call: "search" for
   * fuzzy and partial lookups when SUNDER_SEARCH_UNLOCK is on, "tokens" for
   * the bulk vault routes. It lives about a minute and is spent by ONE call.
   *
   * Requires the admin.unlock action, and the server refuses to grant that to
   * a credential with no expiry: a standing key to every gated surface is not
   * something an audit can reconstruct after the fact.
   */
  async unlock(purpose: string, options?: RequestOptions): Promise<UnlockResult> {
    return this.request<UnlockResult>({
      method: "POST",
      path: "/v1/admin/unlock",
      body: { purpose },
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

  /**
   * Readiness check (GET /readyz). Unlike health it reports whether the
   * backing store and keystore are actually usable, so it is the one to gate
   * traffic on.
   */
  async ready(options?: RequestOptions): Promise<HealthResult> {
    let res: Response;
    try {
      res = await this.fetchOnce("GET", "/readyz", undefined, options);
    } catch (err) {
      throw new SunderError(
        "ServiceUnavailable",
        `network failure calling GET /readyz: ${String(err)}`,
        0,
      );
    }
    const text = await res.text();
    if (!res.ok) {
      throw new SunderError(
        mapError(res.status, undefined),
        `readiness check failed: HTTP ${res.status}`,
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
        res = await this.fetchOnce(
          call.method,
          call.path,
          call.rawBody ?? call.body,
          call.options,
          call.headers,
          call.rawBody !== undefined,
        );
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
    extraHeaders?: Record<string, string>,
    rawBody = false,
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
    if (this.userId !== undefined) headers["X-Sunder-User-Id"] = this.userId;
    for (const [k, v] of Object.entries(extraHeaders ?? {})) headers[k] = v;
    const init: RequestInit = {
      method,
      headers,
      signal: combined,
    };
    if (body !== undefined) {
      if (rawBody) {
        // FormData sets its own multipart Content-Type with the boundary;
        // setting one here would produce a body the server cannot parse.
        init.body = body as BodyInit;
      } else {
        headers["Content-Type"] = "application/json";
        init.body = JSON.stringify(body);
      }
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
