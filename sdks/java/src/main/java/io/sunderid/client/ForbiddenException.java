package io.sunderid.client;

/** Action not allowed for this client (403, error "forbidden"). */
public class ForbiddenException extends SunderException {

    private static final long serialVersionUID = 1L;

    public ForbiddenException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
