package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Draft-11 auth token endpoint (§7.2.1, §6.7.2, §9.4.1): presented_token cross-checks. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsAuthTokenDraft11HttpTest {

    private static final String PS_ORIGIN = "http://localhost";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String RESOURCE_ISS = "https://rs.example";
    private static final String AGENT_ID = "aauth:planner.7f3c@agent-server.example";

    private static final KeyPair AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair OTHER_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AS_KEY = KeyPairs.generateEd25519();
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();

    private static Map<String, Object> jwk(KeyPair keyPair, String kid) {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), kid));
    }

    @TestConfiguration
    static class Config {
        @Bean
        PsSettings psSettings() {
            return new PsSettings(
                    PS_ORIGIN,
                    false,
                    null,
                    null,
                    "user",
                    false,
                    true,
                    null,
                    "stub-agent-jwt",
                    600,
                    null,
                    null,
                    3600,
                    null,
                    null,
                    null,
                    null);
        }

        @Bean
        PsContainer psContainer(PsSettings settings) {
            return PsWiring.buildMemoryPs(PsWiring.Options.builder(settings.origin())
                    .insecureDev(false)
                    .signingKeyPath(null)
                    .trustFile(null)
                    .consentScopesFile(null)
                    .selfJwksProvider(() -> Map.of("keys", List.of(jwk(AS_KEY, "as-kid"))))
                    .resourceJwks(iss -> RESOURCE_ISS.equals(iss.replaceAll("/+$", ""))
                            ? Map.of("keys", List.of(jwk(RS_KEY, "rs-kid")))
                            : null)
                    .build());
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    private static long inOneHour() {
        return Instant.now().getEpochSecond() + 3600;
    }

    private static String agentToken(long exp) {
        return AgentTokens.create(
                AgentTokens.Spec.builder(PS_ORIGIN, AGENT_ID, jwk(AGENT_KEY, "eph"), AS_KEY.getPrivate(), "as-kid")
                        .exp(exp)
                        .build());
    }

    private static String agentJkt() {
        return Jwk.thumbprint(jwk(AGENT_KEY, "eph"));
    }

    private String personToken(KeyPair boundKey, String resource) {
        return personToken(boundKey, resource, null);
    }

    private String personToken(KeyPair boundKey, String resource, String tenant) {
        PersonTokenRequest request = new PersonTokenRequest(
                AGENT_ID, jwk(boundKey, "eph"), resource, null, tenant, inOneHour(), null, null, null, null);
        return ps.personTokenIssuer().issue(request, "user").personToken();
    }

    /** A resource token derived from {@code presented} (what a draft-11 resource issues). */
    private static String resourceToken(
            String presented, String scope, String aud, String subOverride, String jtiOverride) {
        Map<String, Object> claims = Jwts.parse(presented).payload();
        return ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE_ISS,
                aud,
                agentJkt(),
                scope,
                PS_ORIGIN,
                subOverride != null ? subOverride : String.valueOf(claims.get("sub")),
                jtiOverride != null ? jtiOverride : String.valueOf(claims.get("jti")),
                RS_KEY.getPrivate(),
                "rs-kid",
                inOneHour(),
                (String) claims.get("mission_s256"),
                (String) claims.get("tenant"),
                null,
                null));
    }

    private static String resourceToken(String presented) {
        return resourceToken(presented, "demo.scope", PS_ORIGIN, null, null);
    }

    private MvcResult postAuthToken(Map<String, Object> params, String agentToken) throws Exception {
        return signedPost("/auth-token", params, agentToken, null);
    }

    private MvcResult signedPost(String path, Map<String, Object> params, String agentToken, Long created)
            throws Exception {
        byte[] body = Json.write(params).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + path)
                .headers(Map.of("Host", "localhost", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(AGENT_KEY)
                .scheme(new SignatureScheme.Jwt(agentToken))
                .additionalComponents(BODY_COMPONENTS)
                .created(created)
                .build());
        var request = post(path).contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private MvcResult postAuthToken(String resourceToken, String presentedToken) throws Exception {
        return postAuthToken(
                Map.of("resource_token", resourceToken, "presented_token", presentedToken), agentToken(inOneHour()));
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static void assertProblem(MvcResult result, int status, String error) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(json(result)).containsEntry("error", error);
    }

    @Test
    void threePartyFlowIssuesADraft11AuthToken() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        MvcResult result = postAuthToken(resourceToken(person), person);
        assertThat(result.getResponse().getStatus()).isEqualTo(200);

        String authToken = (String) json(result).get("auth_token");
        Map<String, Object> claims = AuthTokens.verifyToken(
                authToken, iss -> ps.psSigning().getJwks(), AuthTokens.VerifyOptions.forType(AuthTokens.TYPE));
        assertThat(claims)
                .containsEntry("iss", PS_ORIGIN)
                .containsEntry("ps", PS_ORIGIN)
                .containsEntry("aud", RESOURCE_ISS)
                .containsEntry("sub", Jwts.parse(person).claim("sub"))
                .doesNotContainKeys("agent", "act", "mission");
        assertThat(((Number) claims.get("exp")).longValue())
                .isLessThanOrEqualTo(Jwts.parse(person).numericClaim("exp"));
        assertThat(((Number) json(result).get("expires_in")).longValue())
                .isPositive()
                .isLessThanOrEqualTo(3600);
    }

    @Test
    void anAuthTokenCanBeThePresentedToken() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        String authToken =
                (String) json(postAuthToken(resourceToken(person), person)).get("auth_token");

        MvcResult stepUp = postAuthToken(resourceToken(authToken), authToken);
        assertThat(stepUp.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void presentedTokenIsRequired() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        MvcResult result = postAuthToken(Map.of("resource_token", resourceToken(person)), agentToken(inOneHour()));
        assertProblem(result, 400, "invalid_request");
    }

    @Test
    void resourceTokenMustNameThePresentedJti() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        assertProblem(
                postAuthToken(resourceToken(person, "demo.scope", PS_ORIGIN, null, "some-other-jti"), person),
                400,
                "invalid_resource_token");
    }

    @Test
    void resourceTokenMustCarryThePresentedSub() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        assertProblem(
                postAuthToken(resourceToken(person, "demo.scope", PS_ORIGIN, "someone-else", null), person),
                400,
                "invalid_resource_token");
    }

    @Test
    void presentedTokenMustBeBoundToTheSigningKey() throws Exception {
        String foreign = personToken(OTHER_KEY, RESOURCE_ISS);
        assertProblem(postAuthToken(resourceToken(foreign), foreign), 400, "invalid_presented_token");
    }

    @Test
    void presentedTokenMustBeForTheResourceThatIssuedTheResourceToken() throws Exception {
        String elsewhere = personToken(AGENT_KEY, "https://elsewhere.example");
        assertProblem(postAuthToken(resourceToken(elsewhere), elsewhere), 400, "invalid_presented_token");
    }

    @Test
    void presentedTokenMustBeAPersonOrAuthToken() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        assertProblem(postAuthToken(resourceToken(person), agentToken(inOneHour())), 400, "invalid_presented_token");
    }

    @Test
    void resourceTokenForAnotherServerIsRejected() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        assertProblem(
                postAuthToken(resourceToken(person, "demo.scope", "https://as.example", null, null), person),
                400,
                "invalid_resource_token");
    }

    @Test
    void failingAgentTokenIsA401WithSignatureError() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        MvcResult result = postAuthToken(
                Map.of("resource_token", resourceToken(person), "presented_token", person),
                agentToken(Instant.now().getEpochSecond() - 10));
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getHeader("Signature-Error")).isEqualTo("error=expired_jwt");
    }

    @Test
    void updatedRequestMustKeepTheOriginalBinding() throws Exception {
        // §7.5.2.2: a consistent but different (resource, presented) pair — here a new tenant —
        // must not replace the original request.
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        MvcResult deferred = postAuthToken(resourceToken(person, "require:user", PS_ORIGIN, null, null), person);
        assertThat(deferred.getResponse().getStatus()).isEqualTo(202);
        String pendingId = (String) json(deferred).get("pending_id");

        String otherTenant = personToken(AGENT_KEY, RESOURCE_ISS, "tenant-2");
        String update = resourceToken(otherTenant, "require:user", PS_ORIGIN, null, null);
        Throwable thrown = catchThrowable(
                () -> ps.tokenBroker().postUpdatedRequest(pendingId, AGENT_ID, update, null, otherTenant));
        assertThat(thrown).isInstanceOf(ProblemError.class).hasMessageContaining("changes tenant");

        String samePerson = personToken(AGENT_KEY, RESOURCE_ISS);
        String valid = resourceToken(samePerson, "require:user", PS_ORIGIN, null, null);
        assertThat(ps.tokenBroker()
                        .postUpdatedRequest(pendingId, AGENT_ID, valid, null, samePerson)
                        .pendingId())
                .isEqualTo(pendingId);
    }

    private static String jti(String token) {
        return Jwts.parse(token).claim("jti");
    }

    @Test
    void revokedPresentedTokenIsReportedAsRevoked() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        ps.revocations().revoke(PS_ORIGIN, jti(person), inOneHour());

        assertProblem(postAuthToken(resourceToken(person), person), 400, ProblemError.REVOKED_PRESENTED_TOKEN);
    }

    @Test
    void revokedResourceTokenIsReportedAsRevoked() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        String resource = resourceToken(person);
        ps.revocations().revoke(RESOURCE_ISS, jti(resource), inOneHour());

        assertProblem(postAuthToken(resource, person), 400, ProblemError.REVOKED_RESOURCE_TOKEN);
    }

    @Test
    void revokedAgentTokenIsA401RevokedJwt() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        String agent = agentToken(inOneHour());
        Map<String, Object> params = Map.of("resource_token", resourceToken(person), "presented_token", person);
        assertThat(postAuthToken(params, agent).getResponse().getStatus()).isEqualTo(200);
        assertThat(ps.revocations().agentSub(PS_ORIGIN, jti(agent))).isEqualTo(AGENT_ID);

        ps.revocations().revoke(PS_ORIGIN, jti(agent), inOneHour());
        MvcResult refused = postAuthToken(params, agent);
        assertThat(refused.getResponse().getStatus()).isEqualTo(401);
        assertThat(refused.getResponse().getHeader("Signature-Error")).isEqualTo("error=revoked_jwt");

        // §11.12.4: the agent-person binding is unchanged; a fresh agent token works.
        assertThat(postAuthToken(params, agentToken(inOneHour())).getResponse().getStatus())
                .isEqualTo(200);
    }

    @Test
    void signatureCreatedAheadOfTheClockIsClockSkewOnDraft11Only() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        Map<String, Object> params = Map.of("resource_token", resourceToken(person), "presented_token", person);
        long ahead = Instant.now().getEpochSecond() + 300;

        MvcResult draft11 = signedPost("/auth-token", params, agentToken(inOneHour()), ahead);
        assertThat(draft11.getResponse().getStatus()).isEqualTo(401);
        assertThat(draft11.getResponse().getHeader("Signature-Error")).isEqualTo("error=clock_skew");

        MvcResult draft10 = signedPost("/token", params, agentToken(inOneHour()), ahead);
        assertThat(draft10.getResponse().getStatus()).isEqualTo(401);
        assertThat(json(draft10)).containsEntry("error", "invalid_signature");
    }

    @Test
    void presentedAuthTokenLongerThanAnHourIsInvalid() throws Exception {
        String person = personToken(AGENT_KEY, RESOURCE_ISS);
        String authToken =
                (String) json(postAuthToken(resourceToken(person), person)).get("auth_token");
        Jwts.Decoded decoded = Jwts.parse(authToken);
        Map<String, Object> payload = new LinkedHashMap<>(decoded.payload());
        payload.put("iat", ((Number) payload.get("exp")).longValue() - 7200);
        String stretched = Jwts.signEdDsa(
                decoded.header(), payload, ps.psSigning().keyPair().getPrivate());

        assertProblem(postAuthToken(resourceToken(stretched), stretched), 400, ProblemError.INVALID_PRESENTED_TOKEN);
    }
}
