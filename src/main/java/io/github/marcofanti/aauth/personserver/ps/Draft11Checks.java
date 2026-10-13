package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * Draft-11 auth token request verification (§6.7.2, §7.2.1): the resource token and the
 * presented token are each verified, then cross-checked so the resource token provably derives
 * from the token the agent presented to the resource.
 */
final class Draft11Checks {

    private static final String PERSON_TYPE = "aa-person+jwt";
    private static final String AUTH_TYPE = "aa-auth+jwt";
    private static final long MAX_LIFETIME_SECONDS = 3600;

    private final String psOrigin;
    private final Function<String, Map<String, Object>> resourceJwks;
    private final Function<String, Map<String, Object>> ownJwks;
    private final RevocationStore revocations;
    private final UpstreamTokens upstreamTokens;

    Draft11Checks(
            String psOrigin,
            Function<String, Map<String, Object>> resourceJwks,
            Function<String, Map<String, Object>> ownJwks,
            RevocationStore revocations,
            UpstreamTokens upstreamTokens) {
        this.psOrigin = MissionUtils.stripTrailingSlash(psOrigin);
        this.resourceJwks = resourceJwks;
        this.ownJwks = ownJwks;
        this.revocations = revocations;
        this.upstreamTokens = upstreamTokens;
    }

    /** Verify both tokens and their binding; returns the verified resource token claims. */
    Map<String, Object> verify(TokenRequest request) {
        if (!request.secureMode() || request.agentJkt() == null) {
            throw new ProblemError(400, "invalid_request", "draft-11 auth token requests require scheme=jwt");
        }
        Map<String, Object> resource = verifyResourceToken(request);
        Map<String, Object> presented = verifyPresentedToken(request.draft11().presentedToken(), resource);
        crossCheck(resource, presented, request.agentJkt());
        if (request.upstreamToken() != null) {
            upstreamTokens.verify(
                    request.upstreamToken(),
                    Jwts.parse(request.draft11().agentToken()).claim("iss"));
        }
        return resource;
    }

    private Map<String, Object> verifyResourceToken(TokenRequest request) {
        Map<String, Object> claims;
        try {
            claims = ResourceTokens.verify(request.resourceToken(), resourceJwks, null, request.agentJkt());
        } catch (TokenException e) {
            requireNotRevoked(request.resourceToken(), ProblemError.REVOKED_RESOURCE_TOKEN);
            throw tokenProblem(e, "invalid_resource_token", "expired_resource_token");
        }
        requireNotRevoked(request.resourceToken(), ProblemError.REVOKED_RESOURCE_TOKEN);
        // aud is this PS (three-party) or the resource's AS (four-party, §9.1); ps is always this PS.
        if (!(claims.get("aud") instanceof String aud) || aud.isBlank()) {
            throw new ProblemError(400, "invalid_resource_token", "resource token has no aud");
        }
        if (!psOrigin.equals(MissionUtils.stripTrailingSlash(String.valueOf(claims.get("ps"))))) {
            throw new ProblemError(400, "invalid_resource_token", "resource token ps does not name this PS");
        }
        revocations.recordResourceIssuer(String.valueOf(claims.get("iss")));
        return claims;
    }

    /** §6.7.2: verify by typ, with aud = the resource token's iss. */
    private Map<String, Object> verifyPresentedToken(String token, Map<String, Object> resource) {
        if (token == null || token.isBlank()) {
            throw new ProblemError(400, "invalid_request", "presented_token is required");
        }
        Object typ;
        try {
            typ = Jwts.parse(token).header().get("typ");
        } catch (RuntimeException e) {
            throw new ProblemError(400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token is not a JWT");
        }
        if (!PERSON_TYPE.equals(typ) && !AUTH_TYPE.equals(typ)) {
            throw new ProblemError(
                    400,
                    ProblemError.INVALID_PRESENTED_TOKEN,
                    "presented_token typ must be aa-person+jwt or aa-auth+jwt");
        }
        String resourceIss = String.valueOf(resource.get("iss"));
        Map<String, Object> claims;
        try {
            claims = PERSON_TYPE.equals(typ)
                    ? PersonTokens.verify(token, issuerJwks(), resourceIss)
                    : AuthTokens.verifyToken(
                            token, issuerJwks(), new AuthTokens.VerifyOptions(AUTH_TYPE, null, resourceIss, null));
        } catch (TokenException e) {
            requireNotRevoked(token, ProblemError.REVOKED_PRESENTED_TOKEN);
            throw tokenProblem(e, ProblemError.INVALID_PRESENTED_TOKEN, ProblemError.EXPIRED_PRESENTED_TOKEN);
        }
        requireNotRevoked(token, ProblemError.REVOKED_PRESENTED_TOKEN);
        if (AUTH_TYPE.equals(typ)) {
            requireBoundedLifetime(claims);
        }
        return claims;
    }

    /** §11.5.2: an auth token carries {@code iat}, and {@code exp - iat} is at most one hour. */
    private static void requireBoundedLifetime(Map<String, Object> claims) {
        if (!(claims.get("iat") instanceof Number iat) || !(claims.get("exp") instanceof Number exp)) {
            throw new ProblemError(400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token lacks iat or exp");
        }
        if (exp.longValue() - iat.longValue() > MAX_LIFETIME_SECONDS) {
            throw new ProblemError(
                    400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token lifetime exceeds one hour");
        }
    }

    /** §11.12.5: a revoked token is reported as revoked, not as malformed or expired. */
    private void requireNotRevoked(String token, String code) {
        Jwts.Decoded decoded;
        try {
            decoded = Jwts.parse(token);
        } catch (RuntimeException e) {
            return;
        }
        Object iss = decoded.payload().get("iss");
        Object jti = decoded.payload().get("jti");
        if (iss instanceof String issuer && jti instanceof String id && revocations.isRevoked(issuer, id)) {
            throw new ProblemError(400, code, "the token's issuer has revoked it");
        }
    }

    /** Presented tokens this PS verifies are ones it issued; others arrive with federation. */
    private Function<String, Map<String, Object>> issuerJwks() {
        return iss -> psOrigin.equals(MissionUtils.stripTrailingSlash(iss)) ? ownJwks.apply(iss) : null;
    }

    private static void crossCheck(Map<String, Object> resource, Map<String, Object> presented, String agentJkt) {
        Object cnf = presented.get("cnf");
        Object jwk = cnf instanceof Map<?, ?> cnfMap ? cnfMap.get("jwk") : null;
        if (!(jwk instanceof Map<?, ?> jwkMap)) {
            throw new ProblemError(400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token has no cnf.jwk");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> key = (Map<String, Object>) jwkMap;
        if (!agentJkt.equals(Jwk.thumbprint(key))) {
            throw new ProblemError(
                    400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token cnf.jwk does not match agent_jkt");
        }
        requireSame(resource, "presented_jti", presented, "jti");
        String presentedIssuer = presented.containsKey("ps") ? "ps" : "iss";
        requireSame(resource, "ps", presented, presentedIssuer);
        requireSame(resource, "sub", presented, "sub");
        requireSame(resource, "mission_s256", presented, "mission_s256");
        requireSame(resource, "tenant", presented, "tenant");
    }

    private static void requireSame(
            Map<String, Object> resource, String resourceClaim, Map<String, Object> presented, String presentedClaim) {
        if (!Objects.equals(resource.get(resourceClaim), presented.get(presentedClaim))) {
            throw new ProblemError(
                    400,
                    "invalid_resource_token",
                    "resource token " + resourceClaim + " does not match the presented token's " + presentedClaim);
        }
    }

    /** Latest {@code exp} the auth token may carry: the agent token and the presented token (§9.4.1). */
    static Long maxExp(TokenRequest request) {
        if (request.draft11() == null) {
            return null;
        }
        Long presentedExp = null;
        try {
            presentedExp = Jwts.parse(request.draft11().presentedToken()).numericClaim("exp");
        } catch (RuntimeException e) {
            throw new ProblemError(400, ProblemError.INVALID_PRESENTED_TOKEN, "presented_token is not a JWT");
        }
        Long cap = earliest(request.draft11().agentTokenExp(), presentedExp);
        if (request.upstreamToken() != null) {
            // §9.4.1: an auth token issued on a request carrying upstream_token does not outlive it.
            cap = earliest(cap, Jwts.parse(request.upstreamToken()).numericClaim("exp"));
        }
        return cap;
    }

    private static Long earliest(Long a, Long b) {
        if (a == null) {
            return b;
        }
        return b == null ? a : Math.min(a, b);
    }

    /** {@link #maxExp(TokenRequest)}, further capped at the mission's {@code expires_at} (§9.4.1). */
    static Long maxExp(TokenRequest request, MissionStatePort missions) {
        Long cap = maxExp(request);
        if (cap == null || request.mission() == null) {
            return cap;
        }
        Long missionCap = Draft11MissionStatus.capFor(
                missions.getMission(request.mission().s256()));
        return missionCap == null ? cap : Math.min(cap, missionCap);
    }

    private static ProblemError tokenProblem(TokenException e, String invalidCode, String expiredCode) {
        String message = String.valueOf(e.getMessage());
        boolean expired = message.toLowerCase(Locale.ROOT).contains("expired");
        return new ProblemError(400, expired ? expiredCode : invalidCode, message);
    }
}
