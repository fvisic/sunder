package io.sunderid.client;

/** Per-client rate limit exceeded (429). */
public class RateLimitedException extends SunderException {

    private static final long serialVersionUID = 1L;

    public RateLimitedException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
