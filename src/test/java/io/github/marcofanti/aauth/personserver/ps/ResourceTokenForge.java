package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Signs draft-11 resource tokens from explicit claims. The library's {@code ResourceTokens.create}
 * derives the binding from a verified presented token, so it cannot produce the mismatched
 * tokens the PS must reject; tests forge those here, with the library's own claim layout.
 */
public final class ResourceTokenForge {

    private ResourceTokenForge() {}

    /** A resource token whose binding mirrors {@code presented}, with {@code overrides} applied. */
    public static String derivedFrom(
            String presented,
            String resource,
            String aud,
            String agentJkt,
            String scope,
            PrivateKey key,
            String kid,
            Map<String, Object> overrides) {
        Map<String, Object> source = Jwts.parse(presented).payload();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", aud);
        claims.put("ps", source.containsKey("ps") ? source.get("ps") : source.get("iss"));
        claims.put("sub", source.get("sub"));
        claims.put("presented_jti", source.get("jti"));
        claims.put("agent_jkt", agentJkt);
        for (String name : new String[] {"mission_s256", "tenant"}) {
            if (source.get(name) != null) {
                claims.put(name, source.get(name));
            }
        }
        if (scope != null) {
            claims.put("scope", scope);
        }
        claims.putAll(overrides);
        return sign(resource, claims, key, kid);
    }

    /** A resource token from {@code iss} carrying exactly {@code claims} plus the base claims. */
    public static String sign(String iss, Map<String, Object> claims, PrivateKey key, String kid) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", iss);
        payload.put("dwk", ResourceTokens.DWK);
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("iat", now);
        payload.put("exp", now + 300);
        payload.putAll(claims);
        return Jwts.encode(payload, key, kid, ResourceTokens.TYPE);
    }
}
