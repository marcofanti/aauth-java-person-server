package io.github.marcofanti.aauth.personserver.compat10;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.keys.CachingJwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

/**
 * Draft-10 resource-token verification and auth-token emission, for agents and resources that
 * have not moved to draft-11 (the Python reference). Ported from aauth-java-library v0.2.3 and
 * built only on the library's public primitives — no crypto is reimplemented.
 *
 * <p>Delete this package as a unit once the Python reference emits draft-11.
 */
public final class Draft10Tokens {

    private static final String RESOURCE_TYPE = "aa-resource+jwt";
    private static final String AUTH_TYPE = "aa-auth+jwt";
    private static final String RESOURCE_DWK = "aauth-resource.json";
    private static final long FUTURE_IAT_TOLERANCE_SECONDS = 60;

    private Draft10Tokens() {}

    /**
     * A resource token is draft-10 when it names the agent and carries no presented-token
     * binding; draft-11 drops {@code agent} and requires {@code presented_jti}.
     */
    public static boolean isDraft10ResourceToken(String token) {
        Map<String, Object> payload;
        try {
            payload = Jwts.parse(token).payload();
        } catch (RuntimeException e) {
            return false;
        }
        return payload.containsKey("agent") && !payload.containsKey("presented_jti");
    }

    /** Verify a draft-10 {@code aa-resource+jwt} (library v0.2.3 semantics). */
    public static Map<String, Object> verifyResourceToken(
            String token,
            Function<String, Map<String, Object>> jwksFetcher,
            String expectedAgent,
            String expectedAgentJkt) {
        Jwts.Decoded jwt;
        try {
            jwt = Jwts.parse(token);
        } catch (RuntimeException e) {
            throw new TokenException("Malformed resource token: " + e.getMessage(), RESOURCE_TYPE);
        }
        long now = Instant.now().getEpochSecond();
        requireEquals(RESOURCE_TYPE, jwt.header().get("typ"), "token type");
        requireEquals(RESOURCE_DWK, jwt.claim("dwk"), "dwk");

        Long exp = jwt.numericClaim("exp");
        if (exp == null) {
            throw new TokenException("Resource token missing 'exp' claim", RESOURCE_TYPE);
        }
        if (now >= exp) {
            throw new TokenException("Resource token has expired", RESOURCE_TYPE);
        }
        Long iat = jwt.numericClaim("iat");
        if (iat != null && iat > now + FUTURE_IAT_TOLERANCE_SECONDS) {
            throw new TokenException("Resource token iat is in the future", RESOURCE_TYPE);
        }
        if (expectedAgent != null) {
            requireEquals(expectedAgent, jwt.claim("agent"), "agent");
        }
        if (expectedAgentJkt != null && !expectedAgentJkt.equals(jwt.claim("agent_jkt"))) {
            throw new TokenException(
                    "agent_jkt mismatch: expected " + expectedAgentJkt + ", got " + jwt.claim("agent_jkt"),
                    RESOURCE_TYPE);
        }
        for (String claim : List.of("jti", "iss", "aud", "agent", "agent_jkt", "scope")) {
            if (!jwt.payload().containsKey(claim)) {
                throw new TokenException("Resource token missing required '" + claim + "' claim", RESOURCE_TYPE);
            }
        }
        verifySignature(jwt, jwksFetcher);
        return jwt.payload();
    }

    /** Claims for a draft-10 auth token; {@code mission} is the {@code {approver, s256}} object. */
    public record AuthTokenSpec(
            String iss,
            String aud,
            String agent,
            Map<String, Object> cnfJwk,
            String sub,
            String scope,
            long exp,
            Map<String, Object> mission,
            String account) {}

    /** Emit a draft-10 {@code aa-auth+jwt} (agent, act, mission object; dwk aauth-person.json). */
    public static String createAuthToken(AuthTokenSpec spec, PrivateKey privateKey, String kid) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", AUTH_TYPE);
        header.put("alg", "Ed25519");
        header.put("kid", kid);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", spec.iss());
        payload.put("aud", spec.aud());
        payload.put("dwk", "aauth-person.json");
        payload.put("jti", UUID.randomUUID().toString());
        payload.put("agent", spec.agent());
        payload.put("cnf", Map.of("jwk", spec.cnfJwk()));
        payload.put("act", Map.of("sub", spec.agent()));
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", spec.exp());
        putIfPresent(payload, "sub", spec.sub());
        putIfPresent(payload, "scope", spec.scope());
        putIfPresent(payload, "mission", spec.mission());
        putIfPresent(payload, "account", spec.account());
        return Jwts.signEdDsa(header, payload, privateKey);
    }

    private static void verifySignature(Jwts.Decoded jwt, Function<String, Map<String, Object>> jwksFetcher) {
        Object kid = jwt.header().get("kid");
        if (kid == null) {
            throw new TokenException("Token header missing 'kid'", RESOURCE_TYPE);
        }
        Object alg = jwt.header().get("alg");
        if (!"Ed25519".equals(alg) && !"EdDSA".equals(alg)) {
            throw new TokenException("Unsupported token alg: expected Ed25519, got " + alg, RESOURCE_TYPE);
        }
        String iss = jwt.claim("iss");
        Map<String, Object> jwks = iss == null ? null : jwksFetcher.apply(iss);
        if (jwks == null) {
            throw new TokenException("Failed to fetch JWKS from " + iss, RESOURCE_TYPE);
        }
        Map<String, Object> signingKey = CachingJwksFetcher.getKeyByKid(jwks, kid.toString());
        if (signingKey == null) {
            throw new TokenException("Signing key with kid=" + kid + " not found in JWKS", RESOURCE_TYPE);
        }
        PublicKey publicKey;
        try {
            publicKey = Jwk.toPublicKey(signingKey);
        } catch (IllegalArgumentException e) {
            throw new TokenException("Failed to load signing key: " + e.getMessage(), RESOURCE_TYPE);
        }
        if (!Jwts.verifySignature(jwt, publicKey)) {
            throw new TokenException("JWT signature verification failed", RESOURCE_TYPE);
        }
    }

    private static void requireEquals(String expected, Object actual, String what) {
        if (!expected.equals(actual)) {
            throw new TokenException("Invalid " + what + ": expected " + expected + ", got " + actual, RESOURCE_TYPE);
        }
    }

    private static void putIfPresent(Map<String, Object> payload, String claim, Object value) {
        if (value != null) {
            payload.put(claim, value);
        }
    }
}
