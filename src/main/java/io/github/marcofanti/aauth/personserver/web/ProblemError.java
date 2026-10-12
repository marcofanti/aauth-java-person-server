package io.github.marcofanti.aauth.personserver.web;

/**
 * A draft-11 error (§11.9.2): rendered as {@code application/problem+json} with an {@code error}
 * code and a {@code detail} explanation. Used on draft-11-only endpoints; draft-10 endpoints keep
 * their {@code error_description} bodies for dual-stack clients.
 */
public final class ProblemError extends RuntimeException {

    // Draft-11 §11.9.3 token endpoint codes not yet in the library's ErrorCodes.
    public static final String INVALID_PRESENTED_TOKEN = "invalid_presented_token";
    public static final String EXPIRED_PRESENTED_TOKEN = "expired_presented_token";
    public static final String REVOKED_PRESENTED_TOKEN = "revoked_presented_token";
    public static final String REVOKED_RESOURCE_TOKEN = "revoked_resource_token";
    public static final String INVALID_SUBAGENT_TOKEN = "invalid_subagent_token";
    public static final String EXPIRED_SUBAGENT_TOKEN = "expired_subagent_token";
    public static final String INVALID_UPSTREAM_TOKEN = "invalid_upstream_token";
    public static final String EXPIRED_UPSTREAM_TOKEN = "expired_upstream_token";
    public static final String REVOKED_UPSTREAM_TOKEN = "revoked_upstream_token";
    public static final String USER_UNREACHABLE = "user_unreachable";
    public static final String RATE_LIMITED = "rate_limited";

    private final int status;
    private final String error;

    public ProblemError(int status, String error, String detail) {
        super(detail);
        this.status = status;
        this.error = error;
    }

    public int status() {
        return status;
    }

    public String error() {
        return error;
    }

    public String detail() {
        return getMessage();
    }
}
