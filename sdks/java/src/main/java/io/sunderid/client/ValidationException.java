package io.sunderid.client;

/** Invalid request (400, error "validation" or "bad_json"), or a client-side precondition failure. */
public class ValidationException extends SunderException {

    private static final long serialVersionUID = 1L;

    public ValidationException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
