package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.personserver.ps.FakeAccessServer;
import io.github.marcofanti.aauth.personserver.ps.FakeAccessServer.Answer;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureInputHeader;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Draft-11 four-party federation (§9.1): the PS calls a real AS and verifies what it delivers. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsFourPartyHttpTest {

    private static final String PS_ORIGIN = "http://localhost";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String RESOURCE_ISS = "https://rs.example";
    private static final String AGENT_ID = "aauth:planner.7f3c@agent-server.example";

    private static final KeyPair AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AP_KEY = KeyPairs.generateEd25519();
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();
    private static final KeyPair STRANGER_KEY = KeyPairs.generateEd25519();
    private static final FakeAccessServer AS = new FakeAccessServer();

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
                    .selfJwksProvider(() -> Map.of("keys", List.of(jwk(AP_KEY, "ap-kid"))))
                    .resourceJwks(iss -> RESOURCE_ISS.equals(iss.replaceAll("/+$", ""))
                            ? Map.of("keys", List.of(jwk(RS_KEY, "rs-kid")))
                            : null)
                    .build());
        }
    }

    @AfterAll
    static void stopAccessServer() {
        AS.close();
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    @BeforeEach
    void defaultAccessServer() {
        AS.reset();
    }

    private static long inOneHour() {
        return Instant.now().getEpochSecond() + 3600;
    }

    private static String agentToken() {
        return AgentTokens.create(
                AgentTokens.Spec.builder(PS_ORIGIN, AGENT_ID, jwk(AGENT_KEY, "eph"), AP_KEY.getPrivate(), "ap-kid")
                        .exp(inOneHour())
                        .build());
    }

    private String personToken() {
        PersonTokenRequest request = new PersonTokenRequest(
                AGENT_ID, jwk(AGENT_KEY, "eph"), RESOURCE_ISS, null, null, inOneHour(), null, null, null, null, null);
        return ps.personTokenIssuer().issue(request, "user").personToken();
    }

    /** A four-party resource token: {@code aud} is the resource's AS, {@code ps} is this PS. */
    private static String resourceToken(String presented, String scope) {
        Map<String, Object> claims = Jwts.parse(presented).payload();
        return ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE_ISS,
                AS.origin(),
                Jwk.thumbprint(jwk(AGENT_KEY, "eph")),
                scope,
                PS_ORIGIN,
                String.valueOf(claims.get("sub")),
                String.valueOf(claims.get("jti")),
                RS_KEY.getPrivate(),
                "rs-kid",
                inOneHour(),
                null,
                null,
                null,
                null));
    }

    private MvcResult requestAuthToken(String person) throws Exception {
        return requestAuthToken(person, "calendar.read calendar.write");
    }

    private MvcResult requestAuthToken(String person, String scope) throws Exception {
        byte[] body = Json.write(Map.of("resource_token", resourceToken(person, scope), "presented_token", person))
                .getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + "/auth-token")
                .headers(Map.of("Host", "localhost", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(AGENT_KEY)
                .scheme(new SignatureScheme.Jwt(agentToken()))
                .additionalComponents(BODY_COMPONENTS)
                .build());
        var request = post("/auth-token").contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static void assertProblem(MvcResult result, int status, String error) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(json(result)).containsEntry("error", error);
    }

    private boolean signedByThePs(FakeAccessServer.Received request) {
        SignatureKeyHeader.Parsed key =
                SignatureKeyHeader.parse(request.headers().get("signature-key"));
        assertThat(key.scheme()).isEqualTo("jwks_uri");
        assertThat(key.params()).containsEntry("id", PS_ORIGIN).containsEntry("dwk", "aauth-person.json");
        return SignatureVerifier.verify(VerifyRequest.builder(request.method(), request.uri(AS.origin()))
                .headers(request.headers())
                .body(request.body())
                .signatureHeaders(
                        request.headers().get("signature-input"),
                        request.headers().get("signature"),
                        request.headers().get("signature-key"))
                .jwksFetcher(
                        (id, dwk, kid) -> PS_ORIGIN.equals(id) ? ps.psSigning().getJwks() : null)
                .build());
    }

    @Test
    void theAuthTokenComesFromTheAccessServerAfterVerification() throws Exception {
        String person = personToken();
        MvcResult result = requestAuthToken(person);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        Map<String, Object> claims =
                Jwts.parse((String) json(result).get("auth_token")).payload();
        assertThat(claims).containsEntry("iss", AS.origin()).containsEntry("aud", RESOURCE_ISS);

        FakeAccessServer.Received call = AS.received().getFirst();
        assertThat(call.path()).isEqualTo("/auth-token");
        assertThat(call.json()).containsOnlyKeys("resource_token", "agent_token", "presented_token");
        assertThat(call.json()).containsEntry("presented_token", person);
        assertThat(SignatureInputHeader.parse(call.headers().get("signature-input"))
                        .components())
                .contains("content-type", "content-digest");
        assertThat(signedByThePs(call)).isTrue();
        assertThat(ps.personTokenLedger().presentations(Jwts.parse(person).claim("jti")))
                .containsExactly(
                        new PersonTokenLedger.Presentation(AS.origin(), Jwk.thumbprint(jwk(AGENT_KEY, "eph"))));
    }

    @Test
    void claimsAreAnsweredWithoutSubAndTheDeferredLoopContinues() throws Exception {
        AS.answer(request -> request.path().equals("/auth-token")
                ? new Answer(
                        202,
                        Map.of(
                                "Location", "/pending/claims",
                                "AAuth-Requirement", "requirement=claims",
                                "Retry-After", "0",
                                "Content-Type", "application/json"),
                        Json.write(Map.of("status", "pending", "required_claims", List.of("email"))))
                : Answer.json(
                        200, Map.of("auth_token", AS.authToken(AS.received().getFirst(), Map.of()))));

        MvcResult result = requestAuthToken(personToken());

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        FakeAccessServer.Received claims = AS.received().get(1);
        assertThat(claims.method()).isEqualTo("POST");
        assertThat(claims.path()).isEqualTo("/pending/claims");
        assertThat(claims.json()).doesNotContainKey("sub");
        assertThat(signedByThePs(claims)).isTrue();
    }

    @Test
    void otherDeferredResponsesArePolledWithASignedGet() throws Exception {
        AS.answer(request -> request.path().equals("/auth-token")
                ? new Answer(
                        202,
                        Map.of(
                                "Location",
                                AS.origin() + "/pending/approval",
                                "AAuth-Requirement",
                                "requirement=approval"),
                        "")
                : Answer.json(
                        200, Map.of("auth_token", AS.authToken(AS.received().getFirst(), Map.of()))));

        assertThat(requestAuthToken(personToken()).getResponse().getStatus()).isEqualTo(200);
        FakeAccessServer.Received poll = AS.received().get(1);
        assertThat(poll.method()).isEqualTo("GET");
        assertThat(poll.body()).isEmpty();
        assertThat(signedByThePs(poll)).isTrue();
    }

    @Test
    void aWellFormedAccessServerErrorIsRelayedWithItsStatus() throws Exception {
        AS.answer(request -> Answer.json(403, Map.of("error", "denied", "detail", "policy says no")));
        MvcResult result = requestAuthToken(personToken());
        assertProblem(result, 403, "denied");
        assertThat(json(result)).containsEntry("detail", "policy says no");
    }

    @Test
    void aMalformedAccessServerAnswerIsAsUnreachable() throws Exception {
        AS.answer(request -> new Answer(500, Map.of(), "oops"));
        assertProblem(requestAuthToken(personToken()), 502, ProblemError.AS_UNREACHABLE);
    }

    @Test
    void anAuthTokenFailingDeliveryChecksIsAsUnreachable() throws Exception {
        List<Map<String, Object>> bad = List.of(
                Map.of("sub", "someone-else"),
                Map.of("aud", "https://other-rs.example"),
                Map.of("scope", "calendar.read calendar.admin"),
                Map.of("exp", inOneHour() + 600),
                Map.of("cnf_jwk", jwk(STRANGER_KEY, "other")));
        for (Map<String, Object> overrides : bad) {
            AS.answer(request -> Answer.json(200, Map.of("auth_token", AS.authToken(request, overrides))));
            assertProblem(requestAuthToken(personToken()), 502, ProblemError.AS_UNREACHABLE);
        }
    }

    @Test
    void anAuthTokenSignedByAnotherKeyIsAsUnreachable() throws Exception {
        AS.answer(request -> {
            Jwts.Decoded token = Jwts.parse(AS.authToken(request, Map.of()));
            return Answer.json(
                    200,
                    Map.of("auth_token", Jwts.signEdDsa(token.header(), token.payload(), STRANGER_KEY.getPrivate())));
        });
        assertProblem(requestAuthToken(personToken()), 502, ProblemError.AS_UNREACHABLE);
    }

    @Test
    void aNarrowerScopeIsAccepted() throws Exception {
        AS.answer(request ->
                Answer.json(200, Map.of("auth_token", AS.authToken(request, Map.of("scope", "calendar.read")))));
        MvcResult result = requestAuthToken(personToken());
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String token = (String) json(result).get("auth_token");
        assertThat(AuthTokens.verifyToken(
                        token,
                        iss -> Map.of(
                                "keys", List.of(Jwk.publicKeyToJwk(AS.key().getPublic(), FakeAccessServer.KID))),
                        AuthTokens.VerifyOptions.forType(AuthTokens.TYPE)))
                .containsEntry("scope", "calendar.read");
    }

    @Test
    void afterConsentTheDeferredRequestReceivesTheAccessServersToken() throws Exception {
        MvcResult deferred = requestAuthToken(personToken(), "require:user");
        assertThat(deferred.getResponse().getStatus()).isEqualTo(202);
        String pendingId = (String) json(deferred).get("pending_id");
        assertThat(AS.received()).isEmpty();

        ps.userConsent().recordDecision(pendingId, new UserDecision(true));

        assertThat(ps.pendingStore().getPending(pendingId, false)).isInstanceOf(AuthTokenResponse.class);
        assertThat(AS.received()).hasSize(1);
    }

    @Test
    void afterConsentAnAccessServerFailureEndsTheDeferredRequest() throws Exception {
        AS.answer(request -> new Answer(503, Map.of(), ""));
        MvcResult deferred = requestAuthToken(personToken(), "require:user");
        String pendingId = (String) json(deferred).get("pending_id");

        ps.userConsent().recordDecision(pendingId, new UserDecision(true));

        PendingDeniedException failed = catchThrowableOfType(
                PendingDeniedException.class, () -> ps.pendingStore().getPending(pendingId, false));
        assertThat(failed.reason()).isEqualTo(ProblemError.AS_UNREACHABLE);
    }

    @Test
    void aPresentationIsRecordedEvenWhenTheAccessServerFails() throws Exception {
        AS.answer(request -> new Answer(503, Map.of(), ""));
        String person = personToken();
        assertProblem(requestAuthToken(person), 502, ProblemError.AS_UNREACHABLE);
        assertThat(ps.personTokenLedger().presentations(Jwts.parse(person).claim("jti")))
                .extracting(PersonTokenLedger.Presentation::asIssuer)
                .containsExactly(AS.origin());
    }

    @Test
    void aPendingUrlOffTheAccessServersOriginIsRefused() throws Exception {
        try (FakeAccessServer elsewhere = new FakeAccessServer()) {
            AS.answer(request -> new Answer(
                    202,
                    Map.of(
                            "Location",
                            elsewhere.origin() + "/pending/x",
                            "AAuth-Requirement",
                            "requirement=approval",
                            "Retry-After",
                            "0"),
                    ""));
            assertProblem(requestAuthToken(personToken()), 502, ProblemError.AS_UNREACHABLE);
            assertThat(elsewhere.received()).isEmpty();
        }
    }
}
