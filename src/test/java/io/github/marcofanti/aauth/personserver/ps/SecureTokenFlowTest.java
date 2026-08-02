package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Mode-3 secure {@code POST /token}: real resource tokens, real {@code aa-auth+jwt}. */
class SecureTokenFlowTest {

    private static final String PS_ORIGIN = "http://ps.uma.lab";
    private static final String RESOURCE_ISS = "http://gateway.uma.lab";
    private static final String AGENT_ID = "aauth:agent@portal.uma.lab";

    private final KeyPair resourceKey = KeyPairs.generateEd25519();
    private final KeyPair agentKey = KeyPairs.generateEd25519();
    private final Map<String, Object> resourceJwks = buildJwks(resourceKey, "rk1");

    private static Map<String, Object> buildJwks(KeyPair keyPair, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), kid));
        return Map.of("keys", List.of(jwk));
    }

    private PsContainer securePs() {
        return PsWiring.buildMemoryPs(PsWiring.Options.builder(PS_ORIGIN)
                .signingKeyPath(null)
                .trustFile(null)
                .consentScopesFile(null)
                .resourceJwks(iss -> RESOURCE_ISS.equals(iss) ? resourceJwks : null)
                .build());
    }

    private Map<String, Object> agentCnfJwk() {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(agentKey.getPublic(), null));
    }

    private String agentJkt() {
        return Jwk.thumbprint(agentCnfJwk());
    }

    private String resourceToken(String scope, String aud, Long exp) {
        return ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE_ISS, aud, AGENT_ID, agentJkt(), scope, resourceKey.getPrivate(), "rk1", exp, null));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> tokenPayload(String token) {
        return (Map<String, Object>) AuthTokens.parseTokenClaims(token).get("payload");
    }

    private TokenRequest secureRequest(String scope, String aud) {
        return TokenRequest.builder(AGENT_ID, resourceToken(scope, aud, null))
                .agentCnfJwk(agentCnfJwk())
                .agentJkt(agentJkt())
                .justification("testing")
                .build();
    }

    @Test
    void audPsWithoutConsentScopeIssuesRealAuthTokenImmediately() {
        PsContainer ps = securePs();
        TokenOutcome outcome = ps.tokenBroker().requestToken(secureRequest("read", PS_ORIGIN));
        assertThat(outcome).isInstanceOf(AuthTokenResponse.class);
        AuthTokenResponse token = (AuthTokenResponse) outcome;

        Map<String, Object> claims = tokenPayload(token.authToken());
        assertThat(claims).containsEntry("iss", PS_ORIGIN);
        assertThat(claims).containsEntry("aud", RESOURCE_ISS);
        assertThat(claims).containsEntry("agent", AGENT_ID);
        assertThat(claims).containsEntry("scope", "read");
        assertThat(claims).containsEntry("sub", "user");
        assertThat(claims).containsEntry("dwk", "aauth-person.json");

        List<Map<String, Object>> issued = ps.issuedTokenStore().listIssued();
        assertThat(issued).hasSize(1);
        assertThat(issued.getFirst()).containsEntry("issue_method", "autonomous");
        assertThat(issued.getFirst()).containsEntry("agent_id", AGENT_ID);
    }

    @Test
    void requireUserScopeDefersThenConsentIssuesRealToken() {
        PsContainer ps = securePs();
        TokenOutcome outcome = ps.tokenBroker().requestToken(secureRequest("read require:user", PS_ORIGIN));
        assertThat(outcome).isInstanceOf(DeferredResponse.class);
        DeferredResponse deferred = (DeferredResponse) outcome;

        ConsentContext context = ps.userConsent().getConsentContext(deferred.code());
        assertThat(context.resourceIss()).isEqualTo(RESOURCE_ISS);
        assertThat(context.resourceScope()).isEqualTo("read require:user");

        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
        PendingPollOutcome polled = ps.tokenBroker().getPending(deferred.pendingId(), AGENT_ID);
        assertThat(polled).isInstanceOf(AuthTokenResponse.class);
        Map<String, Object> claims = tokenPayload(((AuthTokenResponse) polled).authToken());
        assertThat(claims).containsEntry("iss", PS_ORIGIN);
        assertThat(ps.issuedTokenStore().listIssued().getFirst()).containsEntry("issue_method", "user_consent");
    }

    @Test
    void nonPsAudienceFallsBackToFakeFederator() {
        PsContainer ps = securePs();
        TokenOutcome outcome = ps.tokenBroker().requestToken(secureRequest("read", "https://other-as.example"));
        assertThat(outcome).isInstanceOf(AuthTokenResponse.class);
        assertThat(((AuthTokenResponse) outcome).authToken()).startsWith("aa-auth.fake.");
    }

    @Test
    void expiredResourceTokenRejectsWithExpiredCode() {
        PsContainer ps = securePs();
        String expired = resourceToken("read", PS_ORIGIN, Instant.now().getEpochSecond() - 10);
        TokenRequest request = TokenRequest.builder(AGENT_ID, expired)
                .agentCnfJwk(agentCnfJwk())
                .agentJkt(agentJkt())
                .build();
        assertThatThrownBy(() -> ps.tokenBroker().requestToken(request))
                .isInstanceOf(ResourceTokenRejectException.class)
                .extracting(e -> ((ResourceTokenRejectException) e).error())
                .isEqualTo("expired_resource_token");
    }

    @Test
    void garbageResourceTokenRejectsWithInvalidCode() {
        PsContainer ps = securePs();
        TokenRequest request = TokenRequest.builder(AGENT_ID, "not-a-jwt")
                .agentCnfJwk(agentCnfJwk())
                .agentJkt(agentJkt())
                .build();
        assertThatThrownBy(() -> ps.tokenBroker().requestToken(request))
                .isInstanceOf(ResourceTokenRejectException.class)
                .extracting(e -> ((ResourceTokenRejectException) e).error())
                .isEqualTo("invalid_resource_token");
    }

    @Test
    void updatedRequestReplacesResourceTokenAndReverifies() {
        PsContainer ps = securePs();
        DeferredResponse deferred =
                (DeferredResponse) ps.tokenBroker().requestToken(secureRequest("read require:user", PS_ORIGIN));
        String replacement = resourceToken("write require:user", PS_ORIGIN, null);
        DeferredResponse updated =
                ps.tokenBroker().postUpdatedRequest(deferred.pendingId(), AGENT_ID, replacement, "new justification");
        assertThat(updated.pendingId()).isEqualTo(deferred.pendingId());
        PendingRecord record = ps.pendingStore().getRecord(deferred.pendingId());
        assertThat(record.verifiedResourceClaims).containsEntry("scope", "write require:user");
        assertThat(record.tokenRequest.justification()).isEqualTo("new justification");
    }

    @Test
    void clarificationRoundsAreLimited() {
        PsContainer ps = securePs();
        DeferredResponse deferred =
                (DeferredResponse) ps.tokenBroker().requestToken(secureRequest("read require:user", PS_ORIGIN));
        for (int round = 0; round < 5; round++) {
            ps.tokenBroker().postClarificationResponse(deferred.pendingId(), AGENT_ID, "answer " + round);
        }
        assertThatThrownBy(() ->
                        ps.tokenBroker().postClarificationResponse(deferred.pendingId(), AGENT_ID, "one too many"))
                .isInstanceOf(ClarificationLimitException.class);
    }
}
