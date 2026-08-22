package io.sunderid.client;

/** OTI failed signature/purpose/shape checks (400, error "token_invalid"). */
public class TokenInvalidException extends SunderException {

    private static final long serialVersionUID = 1L;

    public TokenInvalidException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
