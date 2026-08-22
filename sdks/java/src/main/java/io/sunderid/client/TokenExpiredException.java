package io.sunderid.client;

/** OTI past its 5-minute lifetime (410). */
public class TokenExpiredException extends SunderException {

    private static final long serialVersionUID = 1L;

    public TokenExpiredException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
