package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.ps.RevocationSender;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender.Outcome;
import io.github.marcofanti.aauth.signing.Jwts;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The agent provider's side of revocation (§11.12.2): it remembers the agent tokens it issued
 * and, when a person revokes an agent's binding, revokes that agent's live tokens at the PS each
 * names in {@code ps}. Records are in memory: a token issued before a restart is not revoked and
 * stays valid until its {@code exp}.
 */
public final class AgentTokenRevocation {

    private static final Logger log = LoggerFactory.getLogger(AgentTokenRevocation.class);

    private record Issued(String jti, String agentId, String ps, long exp) {}

    private final RevocationSender sender;
    private final Map<String, Issued> issued = new ConcurrentHashMap<>();

    public AgentTokenRevocation(RevocationSender sender) {
        this.sender = sender;
    }

    /** Remember an agent token just issued; tokens without {@code ps} have no PS to revoke at. */
    public void record(String agentToken) {
        Jwts.Decoded token = Jwts.parse(agentToken);
        String jti = token.claim("jti");
        String ps = token.claim("ps");
        Long exp = token.numericClaim("exp");
        if (jti != null && ps != null && exp != null) {
            issued.put(jti, new Issued(jti, token.claim("sub"), ps, exp));
        }
    }

    /**
     * Revoke every live agent token issued to {@code agentId}, in the background so the person's
     * request does not wait on the PS.
     *
     * @return one future per revocation, completing with its terminal outcome
     */
    public List<CompletableFuture<Outcome>> revokeAll(String agentId) {
        long now = Instant.now().getEpochSecond();
        issued.values().removeIf(token -> token.exp() <= now);
        List<CompletableFuture<Outcome>> revocations = new ArrayList<>();
        for (Issued token : issued.values()) {
            if (token.agentId().equals(agentId)) {
                revocations.add(CompletableFuture.supplyAsync(() -> {
                    Outcome outcome =
                            sender.send(token.ps(), RevocationSender.PERSON_METADATA, token.jti(), token.exp());
                    log.info("agent token {} of {} revoked at {}: {}", token.jti(), agentId, token.ps(), outcome);
                    return outcome;
                }));
            }
        }
        return revocations;
    }
}
