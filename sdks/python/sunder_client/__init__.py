"""Sunder Python SDK - a thin client for the Sunder pseudonymous identity API.

Implements the canonical CidProviderClient interface (docs/DESIGN.md, SDK design rules):
transport, auth, timeouts, retries and error mapping only. Zero cryptography,
zero third-party dependencies (stdlib urllib).

Retry policy (baked in, the SDK design rules (docs/DESIGN.md)):
  - lookups and issue_oti retry once on 5xx / network errors (safe);
  - verify_oti is NEVER blind-retried (single-use token - a retry after an
    ambiguous network failure would legitimately return TokenUsed).
"""

from __future__ import annotations

import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request

__all__ = [
    "SunderClient",
    "SunderError",
    "NotFoundError",
    "UnauthorizedError",
    "ForbiddenError",
    "PurposeNotAllowedError",
    "UnlockRequiredError",
    "AudienceMismatchError",
    "TokenUsedError",
    "TokenExpiredError",
    "TokenInvalidError",
    "RateLimitedError",
    "ValidationError",
    "ServiceUnavailableError",
]

__version__ = "0.5.0"


class SunderError(Exception):
    """Base error for all Sunder API failures.

    Attributes:
        code:   machine-readable error code (the API's JSON "error" field,
                or a synthetic code such as "service_unavailable").
        status: HTTP status code, or None for pure network failures.
        detail: optional human-readable detail from the API.
    """

    def __init__(self, code: str, status: int | None = None, detail: str | None = None):
        self.code = code
        self.status = status
        self.detail = detail
        msg = code if not detail else f"{code}: {detail}"
        super().__init__(msg)


class NotFoundError(SunderError):
    pass


class UnauthorizedError(SunderError):
    pass


class CredentialExpiredError(SunderError):
    """401 credential_expired - the secret is correct but past its expiry;
    rotate it (`sunder client rotate-secret`), do not retry."""


class ConsentDeniedError(SunderError):
    """403 consent_denied - the data subject withdrew consent for this
    purpose. Distinct from PurposeNotAllowedError (a missing client grant)."""


class ForbiddenError(SunderError):
    pass


class PurposeNotAllowedError(SunderError):
    pass


class AudienceMismatchError(SunderError):
    pass


class TokenUsedError(SunderError):
    pass


class TokenExpiredError(SunderError):
    pass


class TokenInvalidError(SunderError):
    pass


class RateLimitedError(SunderError):
    pass


class ValidationError(SunderError):
    pass


class ServiceUnavailableError(SunderError):
    pass


class UnlockRequiredError(SunderError):
    """403 unlock_required - the credential IS entitled, but the call needs a
    single-use unlock token it did not present. Mint one with
    POST /v1/admin/unlock and send it as X-Sunder-Unlock. Deliberately
    distinct from ForbiddenError: "declare bulk/fuzzy intent first" and
    "you lack the action" call for opposite responses."""


# Exact (status, error-code) pairs first; falls through to status-only rules.
_CODE_MAP: dict[str, type[SunderError]] = {
    "unauthorized": UnauthorizedError,
    "credential_expired": CredentialExpiredError,
    "forbidden": ForbiddenError,
    "consent_denied": ConsentDeniedError,
    "purpose_not_allowed": PurposeNotAllowedError,
    "unlock_required": UnlockRequiredError,
    "audience_mismatch": AudienceMismatchError,
    "not_found": NotFoundError,
    "validation": ValidationError,
    "bad_json": ValidationError,
    "token_invalid": TokenInvalidError,
    "token_used": TokenUsedError,
    "token_expired": TokenExpiredError,
    "rate_limited": RateLimitedError,
}

_STATUS_MAP: dict[int, type[SunderError]] = {
    400: ValidationError,
    401: UnauthorizedError,
    403: ForbiddenError,
    404: NotFoundError,
    409: TokenUsedError,
    410: TokenExpiredError,
    429: RateLimitedError,
}


def _map_error(status: int, body: bytes) -> SunderError:
    """Build the taxonomy exception for a non-2xx response."""
    code = ""
    detail = None
    try:
        parsed = json.loads(body.decode("utf-8"))
        if isinstance(parsed, dict):
            code = str(parsed.get("error", "") or "")
            d = parsed.get("detail")
            detail = str(d) if d is not None else None
    except (ValueError, UnicodeDecodeError):
        pass

    if status >= 500:
        return ServiceUnavailableError(code or "service_unavailable", status, detail)
    cls = _CODE_MAP.get(code) or _STATUS_MAP.get(status) or SunderError
    return cls(code or f"http_{status}", status, detail)



def _oti_body(cid: str, purpose: str, audience: str,
              share_attributes: list[str] | None,
              share_predicates: list[dict] | None = None) -> dict:
    body = {"cid": cid, "purpose": purpose, "audience": audience}
    if share_attributes:
        body["share_attributes"] = list(share_attributes)
    if share_predicates:
        body["share_predicates"] = list(share_predicates)
    return body

class SunderClient:
    """Client for a Sunder instance.

    Args:
        url:        base URL of the Sunder instance; defaults to $SUNDER_URL.
        credential: "client_id.secret" bearer credential; defaults to
                    $SUNDER_CREDENTIAL.
        timeout:    per-request timeout in seconds (default 10).
        user_id:    attributes every read to an operator inside the calling
                    system, sent as X-Sunder-User-Id and recorded in the
                    audit chain. CLIENT-ASSERTED and unverifiable by design:
                    Sunder records the claim and proves it was not altered
                    afterwards, not that it was true. Accepts
                    [A-Za-z0-9._@:-], 1-64 characters; anything else is a
                    400 rather than a silent drop.
    """

    def __init__(self, url: str | None = None, credential: str | None = None,
                 timeout: float = 10.0, user_id: str | None = None):
        url = url if url is not None else os.environ.get("SUNDER_URL", "")
        credential = (credential if credential is not None
                      else os.environ.get("SUNDER_CREDENTIAL", ""))
        if not url:
            raise ValueError("Sunder URL required (arg or SUNDER_URL)")
        if not credential:
            raise ValueError("Sunder credential required (arg or SUNDER_CREDENTIAL)")
        self._base = url.rstrip("/")
        self._credential = credential
        self._timeout = timeout
        self._user_id = user_id

    # -- contacts ------------------------------------------------------------

    def register_contact(self, attributes: dict) -> str:
        """Register (or dedup-merge) a contact; returns the caller-scope CID.

        `attributes` is the full request body: email/phone/name (plus the
        plural "emails"/"phones" lists for contacts with several searchable
        identifiers) and an optional nested "attributes" dict of custom
        fields.
        """
        return self._request("POST", "/v1/contacts", body=attributes)["cid"]

    def issue_scoped_cid(self, cid: str, scope: str) -> str:
        """Issue the same person's CID in another scope (linkage-capable)."""
        path = f"/v1/contacts/{urllib.parse.quote(cid, safe='')}/scopes"
        return self._request("POST", path, body={"scope": scope})["cid"]

    # -- lookup (LOOKUP != AUTHENTICATION) -------------------------------------

    def lookup_by_email(self, email: str) -> str:
        """Find a contact by email; returns the caller-scope CID."""
        return self._request("POST", "/v1/lookup", body={"email": email},
                             retry=True)["cid"]

    def lookup_by_phone(self, phone: str) -> str:
        """Find a contact by phone; returns the caller-scope CID."""
        return self._request("POST", "/v1/lookup", body={"phone": phone},
                             retry=True)["cid"]

    def lookup_by_name(self, name: str, email: str | None = None,
                       phone: str | None = None) -> str:
        """Find a contact by name plus a second factor (email or phone).

        A name alone is never an identifier; exactly the API's rule is
        enforced client-side: at least one of email/phone is required.
        """
        if email is None and phone is None:
            raise ValidationError("validation", None, "lookup_by_name requires email or phone as a second factor")
        body: dict = {"name": name}
        if email is not None:
            body["email"] = email
        if phone is not None:
            body["phone"] = phone
        return self._request("POST", "/v1/lookup", body=body, retry=True)["cid"]

    # -- attributes ------------------------------------------------------------

    def get_attribute(self, cid: str, name: str, purpose: str) -> str:
        """Fetch exactly one attribute value (purpose-checked, audited)."""
        path = (f"/v1/contacts/{urllib.parse.quote(cid, safe='')}"
                f"/attributes/{urllib.parse.quote(name, safe='')}"
                f"?purpose={urllib.parse.quote(purpose, safe='')}")
        return self._request("GET", path)["value"]

    # -- OTI ---------------------------------------------------------------------

    def issue_oti(self, cid: str, purpose: str, audience: str,
                  share_attributes: list[str] | None = None,
                  share_predicates: list[dict] | None = None) -> dict:
        """Issue a one-time identifier; returns {"token", "expires_at"}.

        share_predicates: issuer-authorized claims evaluated at verification
        against the issuer's data, e.g. [{"attr": "birthdate",
        "op": "age_gte", "value": 18}]. The verifier receives booleans only.
        """
        return self._request("POST", "/v1/oti",
                             body=_oti_body(cid, purpose, audience,
                                            share_attributes, share_predicates),
                             retry=True)

    def verify_oti(self, token: str, purpose: str, audience: str) -> str:
        """Verify and consume an OTI; returns the verifier's own scoped CID.

        NEVER blind-retried: the token is single-use, so a retry after an
        ambiguous network failure could consume-then-fail as TokenUsed.
        """
        return self.verify_oti_full(token, purpose, audience)["cid"]

    def verify_oti_full(self, token: str, purpose: str, audience: str) -> dict:
        """Like verify_oti but returns the full result: {"cid", and when
        present "shared" (copied attribute names) and "predicates" (each
        {"attr","op","value","result","known"}). For age_gte, known=False
        means the attribute was absent or unparseable - NOT a failed check;
        for exists, known is always True because absence is the answer."""
        return self._request("POST", "/v1/oti/verify",
                             body={"token": token, "purpose": purpose,
                                   "audience": audience})


    # -- consent -------------------------------------------------------------

    def set_consent(self, cid: str, purpose: str, granted: bool) -> dict:
        """Record the person's decision for one purpose.

        Consent gates attribute reads for that purpose: revoking it makes
        get_attribute raise ConsentDeniedError even though the client's own
        grant is unchanged. Every call is appended to the audit chain, and
        that trail SURVIVES erasure - it is the accountability record of what
        was consented to and when.
        """
        return self._request("POST", "/v1/consent",
                             body={"cid": cid, "purpose": purpose,
                                   "granted": bool(granted)})

    def get_consent(self, cid: str) -> list[dict]:
        """List every purpose the caller's scope has recorded for a person.

        A purpose that was never set is ABSENT, not False: "no decision" and
        "refused" are different facts.
        """
        path = f"/v1/consent/{urllib.parse.quote(cid, safe='')}"
        return self._request("GET", path, retry=True).get("consents", [])

    # -- data subject rights -------------------------------------------------

    def dsr_access(self, cid: str) -> dict:
        """Article 15, ORG-WIDE: {"scopes": [...], "audit_trail": [...]}.

        Each scope carries the holdings that do NOT live in the attribute
        blob - value_tokens, files, the RECIPIENTS of shares, and links.
        This crosses scope boundaries on the data subject's behalf, so it
        needs its own grant and is itself audited; never route it through an
        ordinary integration credential.
        """
        path = f"/v1/dsr/access?cid={urllib.parse.quote(cid, safe='')}"
        return self._request("GET", path, retry=True)

    def dsr_export(self, cid: str) -> dict:
        """Article 20 for the CALLER's scope only: the same holdings sections
        in machine-readable form, for portability."""
        path = f"/v1/dsr/export?cid={urllib.parse.quote(cid, safe='')}"
        return self._request("GET", path, retry=True)

    def dsr_erase(self, cid: str, cascade: list[str] | None = None) -> dict:
        """Article 17: erase the person org-wide, queueing one Article 19
        notification per scope that held them.

        `cascade` names the link types ("guardian", "member", "owner") whose
        linked children are erased too. Omitted, the children are LISTED in
        the result and left untouched - an accidental cascade would delete a
        third party's data, so it is opt-in per link type.

        A cascade is one transaction PER PERSON, and the plan is recorded
        before any child is touched: re-issuing the identical call after an
        interruption RESUMES the outstanding children. Once everything is
        done it raises NotFoundError, deliberately indistinguishable from a
        cid that never existed.

        Never retried: it is destructive, and resuming is the caller's call.
        """
        body: dict = {"cid": cid}
        # An empty list must not be sent: absence is what "cascade nothing"
        # looks like on the wire.
        if cascade:
            body["cascade"] = list(cascade)
        return self._request("POST", "/v1/dsr/erase", body=body)

    # -- value tokenization --------------------------------------------------

    def tokenize(self, value: str, type: str | None = None,
                 cid: str | None = None, unique: bool = False,
                 expires_final: str | None = None,
                 sliding_seconds: int | None = None) -> str:
        """Vault one value and return its opaque token.

        cid binds the token to a person in the caller's scope, so erasure and
        the retention sweep destroy it. Omit it ONLY for a scope-wide value
        belonging to no single subject: an unattributed token survives that
        person's erasure. type is "string" (default) or "card", which also
        validates the Luhn checksum.
        """
        body: dict = {"value": value}
        if type is not None:
            body["type"] = type
        if cid is not None:
            body["cid"] = cid
        if unique:
            body["unique"] = True
        if expires_final is not None:
            body["expires_final"] = expires_final
        if sliding_seconds is not None:
            body["sliding_seconds"] = sliding_seconds
        return self._request("POST", "/v1/tokens", body=body)["token"]

    def detokenize(self, token: str) -> str:
        """Resolve a token back to its value.

        Audited per read and, for a cid-bound token, attributed to that
        person's CID - so "who read my tokenized IBAN" is answerable from the
        access trail.
        """
        path = f"/v1/tokens/{urllib.parse.quote(token, safe='')}"
        return self._request("GET", path, retry=True)["value"]

    def delete_token(self, token: str) -> None:
        """Destroy a token and its value. Not retried: it is destructive."""
        path = f"/v1/tokens/{urllib.parse.quote(token, safe='')}"
        self._request("DELETE", path)

    def tokenize_bulk(self, unlock_token: str, items: list[dict]) -> list[str]:
        """Vault many values in one call; tokens come back in input order.

        Bulk surfaces ALWAYS require a single-use unlock token, regardless of
        SUNDER_SEARCH_UNLOCK: one call touching many people is exactly the
        shape a rate limit does not constrain. Get one from unlock("tokens").
        The whole batch is validated before the token is spent, so a rejected
        item does not burn the unlock.
        """
        return self._request("POST", "/v1/tokens/bulk", body={"items": items},
                             extra_headers={"X-Sunder-Unlock": unlock_token}
                             ).get("tokens", [])

    def detokenize_bulk(self, unlock_token: str, tokens: list[str]) -> list[str]:
        """Resolve many tokens in one call. Requires an unlock token."""
        return self._request("POST", "/v1/tokens/bulk/read",
                             body={"tokens": list(tokens)},
                             extra_headers={"X-Sunder-Unlock": unlock_token}
                             ).get("values", [])

    # -- file vault ----------------------------------------------------------

    def upload_file(self, cid: str, filename: str, content: bytes,
                    content_type: str = "application/octet-stream",
                    expires_at: str | None = None) -> dict:
        """Store a file for a person; returns its metadata.

        Each file gets its own data key, wrapped by the person's record key -
        so erasing the person shreds the file even if the object store still
        holds the ciphertext. expires_at (RFC 3339) sets a hard deadline
        after which the file is unreadable and swept.

        Never retried: a retried upload after an ambiguous failure stores the
        file twice.
        """
        boundary = "----SunderFormBoundary" + secrets.token_hex(16)
        head = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n").encode("utf-8")
        tail = f"\r\n--{boundary}--\r\n".encode("utf-8")
        headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
        if expires_at is not None:
            headers["X-Sunder-File-Expiry"] = expires_at
        path = f"/v1/contacts/{urllib.parse.quote(cid, safe='')}/files"
        return self._request("POST", path, extra_headers=headers,
                             raw_body=head + content + tail)

    def list_files(self, cid: str, purpose: str) -> list[dict]:
        """List a person's files (metadata only).

        Purpose-gated and consent-gated like any other read; expired files
        are hidden.
        """
        path = (f"/v1/contacts/{urllib.parse.quote(cid, safe='')}/files"
                f"?purpose={urllib.parse.quote(purpose, safe='')}")
        return self._request("GET", path, retry=True).get("files", [])

    def download_file(self, file_id: str, purpose: str) -> bytes:
        """Download one file's plaintext.

        A download that fails mid-stream ABORTS the connection rather than
        completing a 200 with a short body, so a truncated read surfaces as a
        network error - verify the length, or the sha256 from list_files,
        before treating the bytes as complete.
        """
        path = (f"/v1/files/{urllib.parse.quote(file_id, safe='')}"
                f"?purpose={urllib.parse.quote(purpose, safe='')}")
        headers = {"Authorization": f"Bearer {self._credential}"}
        if self._user_id is not None:
            headers["X-Sunder-User-Id"] = self._user_id
        req = urllib.request.Request(self._base + path, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            # A 404 must surface as the taxonomy error, never as bytes of an
            # error page the caller would write to disk as the file.
            raise _map_error(e.code, e.read()) from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise ServiceUnavailableError("service_unavailable", None,
                                          f"network failure: {e}") from e

    def delete_file(self, file_id: str) -> None:
        """Remove a file. Its name and digest are redacted immediately; the
        ciphertext is collected by the retention sweep. Not retried."""
        self._request("DELETE", f"/v1/files/{urllib.parse.quote(file_id, safe='')}")

    # -- cross-org shares ----------------------------------------------------

    def create_share(self, cid: str, fields: list[str],
                     partner_label: str | None = None,
                     purpose: str | None = None,
                     ttl_seconds: int | None = None) -> dict:
        """Disclose a SNAPSHOT of named fields to a partner.

        The returned uuid is unguessable and, when the server runs with
        SUNDER_SHARES_PUBLIC, is the ONLY credential needed to fetch it -
        treat it as a bearer secret. partner_label identifies the recipient
        in the audit trail and in the Article 15 answer, which is what makes
        "who was my data disclosed to" answerable.
        """
        body: dict = {"cid": cid, "fields": list(fields)}
        if partner_label is not None:
            body["partner_label"] = partner_label
        if purpose is not None:
            body["purpose"] = purpose
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return self._request("POST", "/v1/shares", body=body)

    def fetch_share(self, uuid: str) -> dict:
        """Read a share's fields. An expired, revoked or erased share raises
        NotFoundError."""
        path = f"/v1/shares/{urllib.parse.quote(uuid, safe='')}"
        return self._request("GET", path, retry=True).get("fields", {})

    def revoke_share(self, uuid: str) -> None:
        """Withdraw a share. Precise to (cid, purpose) on the consent path,
        so revoking one never silently withdraws another. Not retried."""
        self._request("DELETE", f"/v1/shares/{urllib.parse.quote(uuid, safe='')}")

    # -- person links --------------------------------------------------------

    def link(self, parent_cid: str, child_cid: str, link_type: str) -> None:
        """Relate two people in the caller's scope.

        Erasing the parent LISTS the children; it never erases them unless
        dsr_erase names the link type.
        """
        self._request("POST", "/v1/links",
                      body={"parent_cid": parent_cid, "child_cid": child_cid,
                            "link_type": link_type})

    def unlink(self, parent_cid: str, child_cid: str) -> None:
        """Remove the relation. Not retried."""
        self._request("DELETE", "/v1/links",
                      body={"parent_cid": parent_cid, "child_cid": child_cid})

    def list_links(self, cid: str) -> list[dict]:
        """Report this person's links, each with the role ("parent" or
        "child") this cid plays in it."""
        path = f"/v1/contacts/{urllib.parse.quote(cid, safe='')}/links"
        return self._request("GET", path, retry=True).get("links", [])

    # -- attribute version history -------------------------------------------

    def list_versions(self, cid: str) -> list[dict]:
        """Report the retained revisions of a person's attributes, newest
        first. How many are kept is the server's SUNDER_VERSIONS_KEEP /
        _TTL decision; history is personal data and is destroyed by erasure
        like everything else."""
        path = f"/v1/contacts/{urllib.parse.quote(cid, safe='')}/versions"
        return self._request("GET", path, retry=True).get("versions", [])

    def get_version_attribute(self, cid: str, version_no: int, name: str,
                              purpose: str) -> str:
        """Read one attribute as it was at a past revision.

        Purpose-gated, consent-gated and audited exactly like a current read:
        an old value is not a lesser secret.
        """
        path = (f"/v1/contacts/{urllib.parse.quote(cid, safe='')}"
                f"/versions/{int(version_no)}"
                f"/attributes/{urllib.parse.quote(name, safe='')}"
                f"?purpose={urllib.parse.quote(purpose, safe='')}")
        return self._request("GET", path, retry=True)["value"]

    # -- external claims -----------------------------------------------------

    def store_external_claim(self, cid: str, envelope: str) -> list[str]:
        """Ingest a signed envelope from a trusted issuer; returns the names
        actually stored.

        Stored attribute names carry the issuer's provenance after an '@'
        separator - which is why '@' is refused in a caller-supplied
        attribute name: an attribute an external issuer vouched for must
        never be impersonable by an ordinary write.
        """
        return self._request("POST", "/v1/claims/external",
                             body={"cid": cid, "envelope": envelope}
                             ).get("stored", [])

    # -- admin ---------------------------------------------------------------

    def unlock(self, purpose: str) -> dict:
        """Mint a single-use token authorizing one privileged call.

        "search" covers fuzzy and partial lookups when SUNDER_SEARCH_UNLOCK
        is on; "tokens" covers the bulk vault routes. It lives about a minute
        and is spent by ONE call. Requires the admin.unlock action, and the
        server refuses to grant that to a credential with no expiry: a
        standing key to every gated surface is not something an audit can
        reconstruct after the fact.
        """
        return self._request("POST", "/v1/admin/unlock", body={"purpose": purpose})

    def ready(self) -> dict:
        """Readiness probe (GET /readyz). Unlike health it reports whether
        the backing store and keystore are actually usable, so it is the one
        to gate traffic on."""
        req = urllib.request.Request(self._base + "/readyz", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return {"status": resp.read().decode("utf-8").strip() or "ok"}
        except urllib.error.HTTPError as e:
            raise _map_error(e.code, e.read()) from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise ServiceUnavailableError("service_unavailable", None,
                                          f"network failure: {e}") from e

    # -- ops -----------------------------------------------------------------

    def health(self) -> dict:
        """Liveness probe (no auth server-side); returns {"status": ...}."""
        req = urllib.request.Request(self._base + "/healthz", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return {"status": resp.read().decode("utf-8").strip() or "ok"}
        except urllib.error.HTTPError as e:
            raise _map_error(e.code, e.read()) from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise ServiceUnavailableError("service_unavailable", None, f"network failure: {e}") from e

    # -- transport ----------------------------------------------------------

    def _request(self, method: str, path: str, body: dict | None = None,
                 retry: bool = False, extra_headers: dict | None = None,
                 raw_body: bytes | None = None) -> dict:
        """One HTTP round trip; a single extra attempt when retry is set
        and the failure is a 5xx or a network error."""
        attempts = 2 if retry else 1
        last_exc: SunderError | None = None
        for _ in range(attempts):
            try:
                return self._do(method, path, body, extra_headers, raw_body)
            except ServiceUnavailableError as e:
                last_exc = e
        assert last_exc is not None
        raise last_exc

    def _do(self, method: str, path: str, body: dict | None,
            extra_headers: dict | None = None,
            raw_body: bytes | None = None) -> dict:
        data = None
        headers = {
            "Authorization": f"Bearer {self._credential}",
            "Accept": "application/json",
        }
        if self._user_id is not None:
            headers["X-Sunder-User-Id"] = self._user_id
        if extra_headers:
            headers.update(extra_headers)
        if raw_body is not None:
            data = raw_body
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self._base + path, data=data,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise _map_error(e.code, e.read()) from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise ServiceUnavailableError("service_unavailable", None, f"network failure: {e}") from e
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise SunderError("bad_response", None, "non-JSON response body") from None
        if not isinstance(parsed, dict):
            raise SunderError("bad_response", None, "unexpected response shape")
        return parsed
