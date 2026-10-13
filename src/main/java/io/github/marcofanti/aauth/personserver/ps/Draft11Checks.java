package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.util.Map;
import java.util.function.Function;

/**
 * Draft-11 auth token request verification (§6.7.2, §7.2.1). The library verifies the resource
 * token, the presented token, and their binding; this class supplies the keys, the revocation
 * state, and the PS-specific rules ({@code ps} is this PS, call-chaining upstream records).
 */
final class Draft11Checks {

    private static final String RESOURCE_DWK = "aauth-resource.json";
    private static final String PERSON_DWK = "aauth-person.json";

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
        String presented = request.draft11().presentedToken();
        if (presented == null || presented.isBlank()) {
            throw new ProblemError(400, "invalid_request", "presented_token is required");
        }
        // aud is this PS (three-party) or the resource's AS (four-party, §9.1); ps is always this PS.
        // Missions are checked by the broker, which also records why one ended.
        Map<String, Object> claims;
        try {
            claims = ResourceTokens.verify(
                    request.resourceToken(),
                    keys(),
                    new ResourceTokens.VerifyOptions(
                            presented,
                            audienceOf(request.resourceToken()),
                            null,
                            psOrigin,
                            request.agentJkt(),
                            revocations::isRevoked,
                            s256 -> true));
        } catch (TokenException e) {
            throw problem(e, "invalid_resource_token");
        }
        revocations.recordResourceIssuer(String.valueOf(claims.get("iss")));
        if (request.upstreamToken() != null) {
            upstreamTokens.verify(request.upstreamToken(), request.draft11().agentToken());
        }
        return claims;
    }

    /** The resource token's own {@code aud}, read before verification to choose the expectation. */
    private static String audienceOf(String resourceToken) {
        try {
            return Jwts.parse(resourceToken).claim("aud");
        } catch (RuntimeException e) {
            throw new ProblemError(400, "invalid_resource_token", "resource_token is not a JWT");
        }
    }

    /**
     * Resource keys come from the resource; presented person and auth tokens are ones this PS
     * issued, so only its own keys verify them. Other issuers arrive only through federation.
     */
    private JwksFetcher keys() {
        return (id, dwk, kid) -> {
            if (RESOURCE_DWK.equals(dwk)) {
                return resourceJwks.apply(id);
            }
            if (PERSON_DWK.equals(dwk) && psOrigin.equals(MissionUtils.stripTrailingSlash(id))) {
                return ownJwks.apply(id);
            }
            return null;
        };
    }

    /** The library's wire error code as a draft-11 problem (§11.9.3). */
    static ProblemError problem(TokenException e, String fallbackCode) {
        String code = e.errorCode() == null ? fallbackCode : e.errorCode();
        return new ProblemError(400, code, String.valueOf(e.getMessage()));
    }

    /** Latest {@code exp} the auth token may carry: the agent token and the presented token (§9.4.1). */
    static Long maxExp(TokenRequest request) {
        if (request.draft11() == null) {
            return null;
        }
        Long presentedExp;
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
}
