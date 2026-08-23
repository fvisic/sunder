package io.sunderid.client;

/** The data subject withdrew consent for this purpose (403, "consent_denied"). */
public class ConsentDeniedException extends SunderException {
    private static final long serialVersionUID = 1L;

    public ConsentDeniedException(String code, int status, String detail) {
        super(code, status, detail);
    }
}
