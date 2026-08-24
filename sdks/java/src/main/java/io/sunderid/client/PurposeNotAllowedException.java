package io.sunderid.client;

/** Purpose not in the caller's allowed purposes (403, error "purpose_not_allowed"). */
public class PurposeNotAllowedException extends SunderException {

    private static final long serialVersionUID = 1L;

    public PurposeNotAllowedException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
