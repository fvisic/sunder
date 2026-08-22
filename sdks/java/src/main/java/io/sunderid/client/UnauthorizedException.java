package io.sunderid.client;

/** Missing or invalid credential (401). */
public class UnauthorizedException extends SunderException {

    private static final long serialVersionUID = 1L;

    public UnauthorizedException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
