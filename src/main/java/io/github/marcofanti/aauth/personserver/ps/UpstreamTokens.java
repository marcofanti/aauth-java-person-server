package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.Delegation;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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

    /** A verified upstream token: whom it stands for and what bounds a token issued on it. */
    public record Upstream(String iss, String jti, String person, String callingAgent, String missionS256, long exp) {}

    /** Where the PS's records about upstream tokens live. */
    public record Records(PersonTokenLedger personTokens, IssuedTokenStore authTokens, RevocationStore revocations) {}

    private final String psOrigin;
    private final Supplier<Map<String, Object>> ownJwks;
    private final Function<String, Map<String, Object>> accessServerJwks;
    private final Function<String, Map<String, Object>> agentJwks;
    private final Records records;

    public UpstreamTokens(
            String psOrigin,
            Supplier<Map<String, Object>> ownJwks,
            Function<String, Map<String, Object>> accessServerJwks,
            Function<String, Map<String, Object>> agentJwks,
            Records records) {
        this.psOrigin = MissionUtils.stripTrailingSlash(psOrigin);
        this.ownJwks = ownJwks;
        this.accessServerJwks = accessServerJwks;
        this.agentJwks = agentJwks;
        this.records = records;
    }

    /**
     * Verify {@code token} for the intermediary that signed the request with
     * {@code intermediaryAgentToken}.
     *
     * @throws ProblemError {@code invalid_upstream_token}, {@code expired_upstream_token}, or
     *     {@code revoked_upstream_token}
     */
    public Upstream verify(String token, String intermediaryAgentToken) {
        Jwts.Decoded decoded;
        try {
            decoded = Jwts.parse(token);
        } catch (RuntimeException e) {
            throw invalid("upstream_token is not a JWT");
        }
        Map<String, Object> claims = verifySignedClaims(token, decoded, intermediaryAgentToken);
        String iss = String.valueOf(claims.get("iss"));
        String jti = String.valueOf(claims.get("jti"));
        PersonTokenLedger.Issued origin =
                PERSON_TYPE.equals(decoded.header().get("typ")) ? personOrigin(jti) : authOrigin(claims);
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

    /**
     * §9.4.5 steps 1–3 by the library: {@code typ}, signature, {@code aud} = the intermediary's
     * agent-token {@code iss}, {@code ps} = this PS, and an auth token's {@code iss} this PS or an
     * AS this PS presented a person token to for that {@code aud} and {@code sub}.
     */
    private Map<String, Object> verifySignedClaims(String token, Jwts.Decoded decoded, String intermediaryAgentToken) {
        Set<String> federated = federatedAccessServers(decoded);
        JwksFetcher keys = (id, dwk, kid) -> switch (dwk == null ? "" : dwk) {
            case "aauth-person.json" -> isSelf(id) ? ownJwks.get() : null;
            case "aauth-access.json" ->
                federated.contains(MissionUtils.stripTrailingSlash(id)) ? accessServerJwks.apply(id) : null;
            case "aauth-agent.json" -> agentJwks.apply(id);
            default -> null;
        };
        try {
            return Delegation.verifyUpstreamToken(
                    token,
                    keys,
                    new Delegation.UpstreamOptions(
                            intermediaryAgentToken, psOrigin, federated, "ps", records.revocations()::isRevoked));
        } catch (TokenException e) {
            throw Draft11Checks.problem(e, ProblemError.INVALID_UPSTREAM_TOKEN);
        }
    }

    /**
     * Keys of {@code asIssuer} for an auth token it issued, when this PS presented a person token
     * to that AS for the token's {@code aud} and {@code sub}; {@code null} for any other AS.
     */
    Map<String, Object> federatedAccessServerJwks(Jwts.Decoded token, String asIssuer) {
        return federatedAccessServers(token).contains(MissionUtils.stripTrailingSlash(asIssuer))
                ? accessServerJwks.apply(asIssuer)
                : null;
    }

    /** ASes this PS presented a person token to for the upstream token's {@code aud} and {@code sub}. */
    private Set<String> federatedAccessServers(Jwts.Decoded decoded) {
        String aud = decoded.claim("aud");
        String sub = decoded.claim("sub");
        if (aud == null || sub == null) {
            return Set.of();
        }
        Set<String> out = new HashSet<>();
        for (PersonTokenLedger.Issued issued : records.personTokens().findBySubject(aud, sub)) {
            for (PersonTokenLedger.Presentation presentation :
                    records.personTokens().presentations(issued.jti())) {
                out.add(presentation.asIssuer());
            }
        }
        return out;
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
