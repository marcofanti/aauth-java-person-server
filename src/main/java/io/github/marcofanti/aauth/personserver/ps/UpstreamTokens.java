package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Call-chaining upstream token verification at the PS (§9.4.5): the token a calling agent
 * presented to an intermediary, which the intermediary now presents as evidence of whom it acts
 * for. Its {@code aud} is the intermediary, and the PS resolves the calling agent and the person
 * from its own records.
 */
public final class UpstreamTokens {

    private static final String PERSON_TYPE = "aa-person+jwt";
    private static final String AUTH_TYPE = "aa-auth+jwt";

    /** A verified upstream token: whom it stands for and what bounds a token issued on it. */
    public record Upstream(String iss, String jti, String person, String callingAgent, String missionS256, long exp) {}

    /** Where the PS's records about upstream tokens live. */
    public record Records(PersonTokenLedger personTokens, IssuedTokenStore authTokens, RevocationStore revocations) {}

    private final String psOrigin;
    private final Supplier<Map<String, Object>> ownJwks;
    private final Function<String, Map<String, Object>> accessServerJwks;
    private final Records records;

    public UpstreamTokens(
            String psOrigin,
            Supplier<Map<String, Object>> ownJwks,
            Function<String, Map<String, Object>> accessServerJwks,
            Records records) {
        this.psOrigin = MissionUtils.stripTrailingSlash(psOrigin);
        this.ownJwks = ownJwks;
        this.accessServerJwks = accessServerJwks;
        this.records = records;
    }

    /**
     * Verify {@code token} for the intermediary whose agent token was issued by {@code intermediaryIss}.
     *
     * @throws ProblemError {@code invalid_upstream_token}, {@code expired_upstream_token}, or
     *     {@code revoked_upstream_token}
     */
    public Upstream verify(String token, String intermediaryIss) {
        if (intermediaryIss == null) {
            throw invalid("the intermediary's agent token has no iss");
        }
        Jwts.Decoded decoded;
        try {
            decoded = Jwts.parse(token);
        } catch (RuntimeException e) {
            throw invalid("upstream_token is not a JWT");
        }
        Object typ = decoded.header().get("typ");
        if (!PERSON_TYPE.equals(typ) && !AUTH_TYPE.equals(typ)) {
            throw invalid("upstream_token typ must be aa-person+jwt or aa-auth+jwt");
        }
        Map<String, Object> claims = verifySignedClaims(token, decoded, typ, intermediaryIss);
        String iss = String.valueOf(claims.get("iss"));
        String jti = String.valueOf(claims.get("jti"));
        PersonTokenLedger.Issued origin = PERSON_TYPE.equals(typ) ? personOrigin(jti) : authOrigin(claims);
        Long revokedAt = records.revocations().agentRevokedAt(origin.agentId());
        long iat = claims.get("iat") instanceof Number n ? n.longValue() : Long.MIN_VALUE;
        if (revokedAt != null && iat <= revokedAt) {
            throw new ProblemError(
                    400, ProblemError.REVOKED_UPSTREAM_TOKEN, "the calling agent's agent token was revoked");
        }
        return new Upstream(
                iss,
                jti,
                origin.person(),
                origin.agentId(),
                claims.get("mission_s256") instanceof String s256 ? s256 : null,
                ((Number) claims.get("exp")).longValue());
    }

    private Map<String, Object> verifySignedClaims(
            String token, Jwts.Decoded decoded, Object typ, String intermediaryIss) {
        Map<String, Object> claims;
        try {
            claims = PERSON_TYPE.equals(typ)
                    ? PersonTokens.verify(token, iss -> isSelf(iss) ? ownJwks.get() : null, intermediaryIss)
                    : AuthTokens.verifyToken(
                            token,
                            iss -> authIssuerJwks(iss, decoded),
                            new AuthTokens.VerifyOptions(AUTH_TYPE, null, intermediaryIss, null));
        } catch (TokenException e) {
            requireNotRevoked(decoded);
            String message = String.valueOf(e.getMessage());
            boolean expired = message.toLowerCase(Locale.ROOT).contains("expired");
            throw new ProblemError(
                    400,
                    expired ? ProblemError.EXPIRED_UPSTREAM_TOKEN : ProblemError.INVALID_UPSTREAM_TOKEN,
                    "upstream_token: " + message);
        }
        requireNotRevoked(decoded);
        if (AUTH_TYPE.equals(typ) && !isSelf(String.valueOf(claims.get("ps")))) {
            throw invalid("the upstream auth token's ps is not this PS");
        }
        return claims;
    }

    /** §9.4.5 step 2: an auth token's iss is this PS, or an AS this PS presented a person token to. */
    private Map<String, Object> authIssuerJwks(String iss, Jwts.Decoded decoded) {
        if (isSelf(iss)) {
            return ownJwks.get();
        }
        String aud = decoded.claim("aud");
        String sub = decoded.claim("sub");
        if (aud == null || sub == null) {
            return null;
        }
        String issuer = MissionUtils.stripTrailingSlash(iss);
        for (PersonTokenLedger.Issued issued : records.personTokens().findBySubject(aud, sub)) {
            for (PersonTokenLedger.Presentation presentation :
                    records.personTokens().presentations(issued.jti())) {
                if (presentation.asIssuer().equals(issuer)) {
                    return accessServerJwks.apply(issuer);
                }
            }
        }
        return null;
    }

    private void requireNotRevoked(Jwts.Decoded decoded) {
        String iss = decoded.claim("iss");
        String jti = decoded.claim("jti");
        if (iss != null && jti != null && records.revocations().isRevoked(iss, jti)) {
            throw new ProblemError(400, ProblemError.REVOKED_UPSTREAM_TOKEN, "the upstream token was revoked");
        }
    }

    /** §9.4.5 step 4 for a person token: the agent this PS issued it to. */
    private PersonTokenLedger.Issued personOrigin(String jti) {
        PersonTokenLedger.Issued issued = records.personTokens().findByJti(jti);
        if (issued == null) {
            throw invalid("this PS holds no record of the upstream person token");
        }
        return issued;
    }

    /**
     * §9.4.5 step 4 for an auth token: the agent this PS issued it to, or, for an AS-issued one,
     * the agent holding the person token presented to that AS for the same resource and person.
     */
    private PersonTokenLedger.Issued authOrigin(Map<String, Object> claims) {
        String aud = String.valueOf(claims.get("aud"));
        String sub = String.valueOf(claims.get("sub"));
        if (isSelf(String.valueOf(claims.get("iss")))) {
            for (Map<String, Object> row : records.authTokens().listIssued()) {
                if (Objects.equals(row.get("token_jti"), claims.get("jti"))) {
                    String agent = String.valueOf(row.get("agent_id"));
                    String person = String.valueOf(row.get("owner_id"));
                    return new PersonTokenLedger.Issued(String.valueOf(claims.get("jti")), agent, person, aud, sub, 0);
                }
            }
            throw invalid("this PS holds no record of the upstream auth token");
        }
        // Several agents of one person share (aud, sub); the AS bound its token to the presenting
        // agent's key, so the presentation made with that key identifies the agent.
        String issuer = MissionUtils.stripTrailingSlash(String.valueOf(claims.get("iss")));
        PersonTokenLedger.Presentation expected = new PersonTokenLedger.Presentation(issuer, cnfThumbprint(claims));
        PersonTokenLedger.Issued latest = null;
        for (PersonTokenLedger.Issued issued : records.personTokens().findBySubject(aud, sub)) {
            if (records.personTokens().presentations(issued.jti()).contains(expected)
                    && (latest == null || issued.exp() > latest.exp())) {
                latest = issued;
            }
        }
        if (latest == null) {
            throw invalid("this PS cannot identify the agent the upstream auth token was issued to");
        }
        return latest;
    }

    private static String cnfThumbprint(Map<String, Object> claims) {
        if (claims.get("cnf") instanceof Map<?, ?> cnf && cnf.get("jwk") instanceof Map<?, ?> jwk) {
            @SuppressWarnings("unchecked")
            Map<String, Object> key = (Map<String, Object>) jwk;
            return Jwk.thumbprint(key);
        }
        return null;
    }

    private boolean isSelf(String iss) {
        return iss != null && psOrigin.equals(MissionUtils.stripTrailingSlash(iss));
    }

    private static ProblemError invalid(String detail) {
        return new ProblemError(400, ProblemError.INVALID_UPSTREAM_TOKEN, detail);
    }
}
