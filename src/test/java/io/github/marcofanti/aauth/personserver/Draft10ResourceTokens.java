package io.github.marcofanti.aauth.personserver;

import io.github.marcofanti.aauth.signing.Jwts;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Mints draft-10 resource tokens the way pre-draft-11 resources (the Python reference, library
 * v0.2.3) do, so tests cover the dual-stack {@code compat10} path.
 */
public final class Draft10ResourceTokens {

    private Draft10ResourceTokens() {}

    public static String create(
            String iss,
            String aud,
            String agent,
            String agentJkt,
            String scope,
            PrivateKey privateKey,
            String kid,
            Long exp,
            Map<String, Object> mission,
            String account) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "aa-resource+jwt");
        header.put("alg", "Ed25519");
        header.put("kid", kid);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss);
        payload.put("aud", aud);
        payload.put("dwk", "aauth-resource.json");
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("agent", agent);
        payload.put("agent_jkt", agentJkt);
        payload.put("iat", now);
        payload.put("exp", exp != null ? exp : now + 600);
        payload.put("scope", scope);
        if (mission != null) {
            payload.put("mission", mission);
        }
        if (account != null) {
            payload.put("account", account);
        }
        return Jwts.signEdDsa(header, payload, privateKey);
    }
}
