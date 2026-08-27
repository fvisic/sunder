package io.sunderid.client;

/**
 * The credential IS entitled, but the call needs a single-use unlock token it
 * did not present (403, error "unlock_required"). Mint one with
 * POST /v1/admin/unlock and send it as X-Sunder-Unlock. Deliberately distinct
 * from {@link ForbiddenException}: "declare bulk/fuzzy intent first" and "you
 * lack the action" call for opposite responses.
 */
public class UnlockRequiredException extends SunderException {

    private static final long serialVersionUID = 1L;

    public UnlockRequiredException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
