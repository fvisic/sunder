package io.sunderid.client;

/** Correct secret, past its expiry - rotate it (401, "credential_expired"). */
public class CredentialExpiredException extends SunderException {
    private static final long serialVersionUID = 1L;

    public CredentialExpiredException(String code, int status, String detail) {
        super(code, status, detail);
    }
}
