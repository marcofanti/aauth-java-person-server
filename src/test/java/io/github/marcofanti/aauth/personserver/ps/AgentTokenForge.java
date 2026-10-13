package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Signs agent tokens the library refuses to mint: a sub-agent naming a parent it was not issued
 * from, or a token that has already expired. Same claim layout as {@code AgentTokens.create}.
 */
public final class AgentTokenForge {

    private AgentTokenForge() {}

    public static String sign(
            String iss,
            String sub,
            Map<String, Object> cnfJwk,
            PrivateKey key,
            String kid,
            long exp,
            String parentAgent) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss);
        payload.put("sub", sub);
        payload.put("dwk", AgentTokens.DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iat", Math.min(Instant.now().getEpochSecond(), exp - 1));
        payload.put("exp", exp);
        payload.put("cnf", Map.of("jwk", cnfJwk));
        if (parentAgent != null) {
            payload.put("parent_agent", parentAgent);
        }
        return Jwts.encode(payload, key, kid, AgentTokens.TYPE);
    }
}
