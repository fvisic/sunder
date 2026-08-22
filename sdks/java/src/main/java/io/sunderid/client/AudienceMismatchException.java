package io.sunderid.client;

/** OTI audience does not match the verifier's scope (403, error "audience_mismatch"). */
public class AudienceMismatchException extends SunderException {

    private static final long serialVersionUID = 1L;

    public AudienceMismatchException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
