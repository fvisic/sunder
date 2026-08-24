package io.sunderid.client;

/** No match (404) - including a person who exists but has no CID in the caller's scope. */
public class NotFoundException extends SunderException {

    private static final long serialVersionUID = 1L;

    public NotFoundException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
