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

__version__ = "0.1.0"


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
    """

    def __init__(self, url: str | None = None, credential: str | None = None,
                 timeout: float = 10.0):
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
                 retry: bool = False) -> dict:
        """One HTTP round trip; a single extra attempt when retry is set
        and the failure is a 5xx or a network error."""
        attempts = 2 if retry else 1
        last_exc: SunderError | None = None
        for _ in range(attempts):
            try:
                return self._do(method, path, body)
            except ServiceUnavailableError as e:
                last_exc = e
        assert last_exc is not None
        raise last_exc

    def _do(self, method: str, path: str, body: dict | None) -> dict:
        data = None
        headers = {
            "Authorization": f"Bearer {self._credential}",
            "Accept": "application/json",
        }
        if body is not None:
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
