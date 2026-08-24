package io.sunderid.client;

/** Server-side failure (5xx) or a network-level failure (status null, code "service_unavailable"). */
public class ServiceUnavailableException extends SunderException {

    private static final long serialVersionUID = 1L;

    public ServiceUnavailableException(String code, Integer status, String detail) {
        super(code, status, detail);
    }
}
