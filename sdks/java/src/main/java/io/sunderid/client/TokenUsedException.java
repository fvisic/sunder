package io.sunderid.client;

/** OTI already consumed (409) — single use is enforced atomically server-side. */
public class TokenUsedException extends SunderException {

    private static final long serialVersionUID = 1L;

    public TokenUsedException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
