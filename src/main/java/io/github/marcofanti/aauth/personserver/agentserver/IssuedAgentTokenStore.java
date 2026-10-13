package io.github.marcofanti.aauth.personserver.agentserver;

import java.util.List;

/**
 * The agent tokens this agent provider issued that name a PS, kept until their {@code exp} so a
 * binding revocation can revoke them at that PS (§11.12.2).
 */
public interface IssuedAgentTokenStore {

    /** One issued agent token: what the PS needs to revoke it, and whose it is. */
    record Issued(String jti, String agentId, String ps, long exp) {}

    /** Remember a token; recording the same {@code jti} again is a no-op. */
    void record(Issued issued);

    /** Unexpired tokens issued to {@code agentId}. */
    List<Issued> liveFor(String agentId, long nowEpochSeconds);

    /** Forget tokens whose {@code exp} has passed. */
    void purgeExpired(long nowEpochSeconds);
}
