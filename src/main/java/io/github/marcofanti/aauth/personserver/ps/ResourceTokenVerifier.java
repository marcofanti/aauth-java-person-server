package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.compat10.Draft10Tokens;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import java.util.Map;
import java.util.function.Function;

/**
 * Resource-token verification on the draft-10 token endpoint. Draft-11 resource tokens are
 * verified with their presented token at {@code auth_token_endpoint} ({@link Draft11Checks}), so
 * one arriving here is refused rather than redeemed without that cross-check.
 */
public final class ResourceTokenVerifier {

    private ResourceTokenVerifier() {}

    /** True when the verified claims are draft-11 shaped. */
    public static boolean isDraft11(Map<String, Object> claims) {
        return claims.containsKey("presented_jti");
    }

    private static boolean isDraft11Shaped(String token) {
        try {
            return Jwts.parse(token).payload().containsKey("presented_jti");
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Verify a draft-10 resource token.
     *
     * @throws io.github.marcofanti.aauth.TokenException if the token is invalid
     * @throws ProblemError {@code invalid_resource_token} for a draft-11 resource token
     */
    public static Map<String, Object> verify(
            String token, Function<String, Map<String, Object>> jwksFetcher, String agentId, String agentJkt) {
        if (isDraft11Shaped(token)) {
            throw new ProblemError(
                    400,
                    "invalid_resource_token",
                    "draft-11 resource tokens are redeemed at auth_token_endpoint with presented_token");
        }
        return Draft10Tokens.verifyResourceToken(token, jwksFetcher, agentId, agentJkt);
    }
}
