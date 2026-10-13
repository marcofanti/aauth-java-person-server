package io.github.marcofanti.aauth.personserver.ps;

/**
 * Draft-11 revocation state (§11.12): revocations keyed by {@code (iss, jti)}, and the agent
 * tokens this PS has accepted, so an agent-token revocation can cascade by the agent's
 * {@code sub} (§11.12.4 Records). Entries may be discarded after their {@code exp}.
 */
public interface RevocationStore {

    /** Remember a resource whose resource token this PS verified; only those may revoke (§11.12.3). */
    void recordResourceIssuer(String iss);

    boolean isKnownResourceIssuer(String iss);

    /** Record a revocation; repeating it is a no-op (§11.12.3 idempotence). */
    void revoke(String iss, String jti, long exp);

    boolean isRevoked(String iss, String jti);

    /** Remember an accepted agent token and the {@code sub} it carried. */
    void recordAgentToken(String iss, String jti, String sub, long exp);

    /** The {@code sub} an accepted agent token carried, or {@code null} if never seen. */
    String agentSub(String iss, String jti);

    /** Record that an agent token of {@code agentSub} was revoked at {@code epochSeconds} (§9.4.5 step 4). */
    void recordAgentRevocation(String agentSub, long epochSeconds);

    /** When an agent token of {@code agentSub} was last revoked, or {@code null} if never. */
    Long agentRevokedAt(String agentSub);

    /** Drop revocations and agent-token records with {@code exp <= cutoffEpochSeconds}. */
    void purgeExpired(long cutoffEpochSeconds);
}
