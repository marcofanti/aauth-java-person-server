package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.compat10.Draft10Tokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.util.Map;
import java.util.function.Function;

/**
 * Dual-stack resource-token verification: draft-11 tokens go through the library's strict
 * verifier; draft-10 tokens (agent named, no {@code presented_jti}) through {@code compat10}.
 */
public final class ResourceTokenVerifier {

    private ResourceTokenVerifier() {}

    /** True when the verified claims are draft-11 shaped. */
    public static boolean isDraft11(Map<String, Object> claims) {
        return claims.containsKey("presented_jti");
    }

    /**
     * Verify a resource token of either draft.
     *
     * @throws io.github.marcofanti.aauth.TokenException if the token is invalid
     */
    public static Map<String, Object> verify(
            String token, Function<String, Map<String, Object>> jwksFetcher, String agentId, String agentJkt) {
        if (Draft10Tokens.isDraft10ResourceToken(token)) {
            return Draft10Tokens.verifyResourceToken(token, jwksFetcher, agentId, agentJkt);
        }
        return ResourceTokens.verify(token, jwksFetcher, null, agentJkt);
    }
}
