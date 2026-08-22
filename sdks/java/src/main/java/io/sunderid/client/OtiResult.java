package io.sunderid.client;

/**
 * Result of {@link SunderClient#issueOti}: a PASETO v4.public one-time
 * identifier, valid for 5 minutes, one use, one audience, one purpose.
 *
 * @param token     the one-time identifier token
 * @param expiresAt RFC 3339 expiry timestamp
 */
public record OtiResult(String token, String expiresAt) {
}
