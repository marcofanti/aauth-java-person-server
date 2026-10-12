package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.compat10.Draft10Tokens;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Issue PS-signed {@code aa-auth+jwt} (SPEC §Auth Token, three-party). */
public final class AuthTokenIssuer {

    private static final Logger log = LoggerFactory.getLogger(AuthTokenIssuer.class);

    private final String iss;
    private final PsSigningService signing;
    private final String userSub;
    private final int lifetimeSeconds;
    private final IssuedTokenStore store;

    public AuthTokenIssuer(
            String psOrigin,
            PsSigningService signing,
            String userSub,
            int authTokenLifetimeSeconds,
            IssuedTokenStore issuedTokenStore) {
        this.iss = MissionUtils.stripTrailingSlash(psOrigin);
        this.signing = signing;
        this.userSub = userSub;
        this.lifetimeSeconds = Math.max(60, Math.min(authTokenLifetimeSeconds, 3600));
        this.store = issuedTokenStore;
    }

    /** Parameters for {@link #issue(IssueSpec)}. */
    public record IssueSpec(
            String agentId,
            Map<String, Object> agentCnfJwk,
            Map<String, Object> resourceClaims,
            MissionRef mission,
            String justification,
            String issueMethod) {

        public IssueSpec {
            issueMethod = issueMethod == null ? "autonomous" : issueMethod;
        }
    }

    public AuthTokenResponse issue(IssueSpec spec) {
        Map<String, Object> resourceClaims = spec.resourceClaims();
        String resourceIss = String.valueOf(resourceClaims.get("iss"));
        String scope = String.valueOf(resourceClaims.getOrDefault("scope", ""));
        Map<String, Object> missionObj = null;
        if (spec.mission() != null) {
            missionObj = Map.of(
                    "approver",
                    spec.mission().approver(),
                    "s256",
                    spec.mission().s256());
        } else if (resourceClaims.get("mission") instanceof Map<?, ?> claimMission) {
            Map<String, Object> copy = new LinkedHashMap<>();
            claimMission.forEach((key, value) -> copy.put(String.valueOf(key), value));
            missionObj = copy;
        }

        // The PS copies the resource token's account claim into the auth token (§12.3).
        String account = stringClaim(resourceClaims, "account");

        long exp = Instant.now().getEpochSecond() + lifetimeSeconds;
        String token = ResourceTokenVerifier.isDraft11(resourceClaims)
                ? issueDraft11(spec, resourceClaims, resourceIss, scope, account, exp)
                : Draft10Tokens.createAuthToken(
                        new Draft10Tokens.AuthTokenSpec(
                                iss,
                                resourceIss,
                                spec.agentId(),
                                spec.agentCnfJwk(),
                                userSub,
                                scope,
                                exp,
                                missionObj,
                                account),
                        signing.keyPair().getPrivate(),
                        signing.kid());

        if (store != null) {
            try {
                store.recordIssued(new IssuedTokenStore.IssuedToken(
                        token,
                        spec.agentId(),
                        userSub,
                        resourceIss,
                        scope.isEmpty() ? null : scope,
                        spec.justification(),
                        spec.issueMethod(),
                        Instant.ofEpochSecond(exp)));
            } catch (RuntimeException e) {
                log.warn("failed to record issued token (never blocks issuance): {}", e.getMessage());
            }
        }

        return new AuthTokenResponse(token, lifetimeSeconds);
    }

    /**
     * Draft-11 auth token (§9.4.1): {@code ps} is this PS, {@code sub} is the resource token's
     * directed identifier, mission rides as {@code mission_s256}; no {@code agent}/{@code act}.
     */
    private String issueDraft11(
            IssueSpec spec,
            Map<String, Object> resourceClaims,
            String resourceIss,
            String scope,
            String account,
            long exp) {
        String missionS256 = stringClaim(resourceClaims, "mission_s256");
        if (missionS256 == null && spec.mission() != null) {
            missionS256 = spec.mission().s256();
        }
        return AuthTokens.create(AuthTokens.Spec.builder(iss, resourceIss, stringClaim(resourceClaims, "sub"), iss)
                .cnfJwk(spec.agentCnfJwk())
                .signingKey(signing.keyPair().getPrivate(), signing.kid())
                .scope(scope.isEmpty() ? null : scope)
                .exp(exp)
                .missionS256(missionS256)
                .dwk("aauth-person.json")
                .account(account)
                .build());
    }

    private static String stringClaim(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String value ? value : null;
    }
}
