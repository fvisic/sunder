package io.sunderid.client;

/**
 * Base exception for all Sunder API failures.
 *
 * <p>Carries the unified error taxonomy shared by every Sunder SDK:
 * <ul>
 *   <li>{@code code}   — machine-readable error code (the API's JSON
 *       {@code "error"} field, or a synthetic code such as
 *       {@code "service_unavailable"});</li>
 *   <li>{@code status} — HTTP status code, or {@code null} for pure
 *       network-level failures;</li>
 *   <li>{@code detail} — optional human-readable detail from the API.</li>
 * </ul>
 */
public class SunderException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final String code;
    private final Integer status;
    private final String detail;

    public SunderException(String code, Integer status, String detail) {
        super(detail == null || detail.isEmpty() ? code : code + ": " + detail);
        this.code = code;
        this.status = status;
        this.detail = detail;
    }

    /** Machine-readable error code, stable across SDK languages. */
    public String getCode() {
        return code;
    }

    /** HTTP status of the response, or {@code null} for network-level failures. */
    public Integer getStatus() {
        return status;
    }

    /** Optional human-readable detail from the API, or {@code null}. */
    public String getDetail() {
        return detail;
    }
}
