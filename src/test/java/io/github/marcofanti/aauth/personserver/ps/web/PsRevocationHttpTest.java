package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.FakeRevocationResource;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Draft-11 revocation endpoint (§11.12) over HTTP, with a real resource receiving the cascade. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsRevocationHttpTest {

    private static final String PS_ORIGIN = "https://ps.example";
    // MockMvc gives an absolute URL without a port the default port 80; name 443 explicitly.
    private static final String REQUEST_BASE = PS_ORIGIN + ":443";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String AGENT_ID = "aauth:planner.7f3c@agent-server.example";

    private static final KeyPair AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AS_KEY = KeyPairs.generateEd25519();
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();
    private static final KeyPair STRANGER_KEY = KeyPairs.generateEd25519();
    private static final FakeRevocationResource RESOURCE = new FakeRevocationResource();
    private static final FakeRevocationResource SLOW_RESOURCE =
            new FakeRevocationResource().delaying(Duration.ofMillis(1500));

    private static Map<String, Object> jwks(KeyPair keyPair, String kid) {
        return Map.of("keys", List.of(Jwk.publicKeyToJwk(keyPair.getPublic(), kid)));
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
                    .selfJwksProvider(() -> jwks(AS_KEY, "as-kid"))
                    .resourceJwks(
                            iss -> RESOURCE.origin().equals(iss.replaceAll("/+$", "")) ? jwks(RS_KEY, "rs-kid") : null)
                    .build());
        }
    }

    @AfterAll
    static void stopResource() {
        RESOURCE.close();
        SLOW_RESOURCE.close();
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    @org.junit.jupiter.api.BeforeEach
    void theResourceHasIssuedTokensToThisPs() {
        ps.revocations().recordResourceIssuer(RESOURCE.origin());
    }

    private static long inOneHour() {
        return Instant.now().getEpochSecond() + 3600;
    }

    private static String agentToken() {
        Map<String, Object> cnf = new LinkedHashMap<>(Jwk.publicKeyToJwk(AGENT_KEY.getPublic(), "eph"));
        return AgentTokens.create(AgentTokens.Spec.builder(PS_ORIGIN, AGENT_ID, cnf, AS_KEY.getPrivate(), "as-kid")
                .exp(inOneHour())
                .build());
    }

    private MvcResult send(String path, byte[] body, KeyPair key, SignatureScheme scheme, List<String> components)
            throws Exception {
        return send(path, body, key, scheme, components, null);
    }

    private MvcResult send(
            String path, byte[] body, KeyPair key, SignatureScheme scheme, List<String> components, Long created)
            throws Exception {
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + path)
                .headers(Map.of("Host", "ps.example", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(key)
                .scheme(scheme)
                .additionalComponents(components)
                .created(created)
                .build());
        MockHttpServletRequestBuilder request =
                post(REQUEST_BASE + path).contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private static byte[] revocation(String jti) {
        return Json.write(Map.of("jti", jti, "exp", inOneHour())).getBytes(StandardCharsets.UTF_8);
    }

    private MvcResult revokeAsAgentProvider(String jti) throws Exception {
        return send(
                "/revoke",
                revocation(jti),
                AS_KEY,
                new SignatureScheme.JwksUri(PS_ORIGIN, "aauth-agent.json", "as-kid"),
                BODY_COMPONENTS);
    }

    private static final SignatureScheme AS_IDENTITY =
            new SignatureScheme.JwksUri(PS_ORIGIN, "aauth-agent.json", "as-kid");

    /** An agent-provider revocation that asks the PS not to hold ({@code Prefer: wait=0}). */
    private MvcResult revokeWithoutWaiting(byte[] body, KeyPair key, SignatureScheme scheme) throws Exception {
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + "/revoke")
                .headers(Map.of("Host", "ps.example", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(key)
                .scheme(scheme)
                .additionalComponents(BODY_COMPONENTS)
                .build());
        MockHttpServletRequestBuilder request = post(REQUEST_BASE + "/revoke")
                .contentType(JSON_UTF8)
                .content(body)
                .header("Prefer", "wait=0");
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private MvcResult poll(String location, KeyPair key, SignatureScheme scheme) throws Exception {
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("GET", location)
                .headers(Map.of("Host", "ps.example"))
                .keyPair(key)
                .scheme(scheme)
                .build());
        MockHttpServletRequestBuilder request =
                get(location.replace(PS_ORIGIN, REQUEST_BASE)).header("Prefer", "wait=20");
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private MvcResult revokeAsResource(byte[] body, KeyPair key) throws Exception {
        return send(
                "/revoke",
                body,
                key,
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-resource.json", "rs-kid"),
                BODY_COMPONENTS);
    }

    private MvcResult agentRequest(String agentToken) throws Exception {
        byte[] body = Json.write(Map.of("description", "Plan a trip")).getBytes(StandardCharsets.UTF_8);
        return send("/agent-missions", body, AGENT_KEY, new SignatureScheme.Jwt(agentToken), BODY_COMPONENTS);
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static void assertSignatureError(MvcResult result, String code) {
        assertThat(result.getResponse().getStatus()).isEqualTo(401);
        assertThat(result.getResponse().getHeader("Signature-Error")).isEqualTo("error=" + code);
    }

    private static void assertProblem(MvcResult result, int status, String error) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getContentType()).startsWith("application/problem+json");
        assertThat(json(result)).containsEntry("error", error);
    }

    @Test
    void metadataAdvertisesTheRevocationEndpoint() throws Exception {
        MvcResult result = mvc.perform(get(REQUEST_BASE + "/.well-known/aauth-person.json"))
                .andReturn();
        assertThat(json(result)).containsEntry("revocation_endpoint", PS_ORIGIN + "/revoke");
    }

    @Test
    void agentProviderRevocationDeniesTheTokenAndCascadesToTheResource() throws Exception {
        String agentToken = agentToken();
        assertThat(agentRequest(agentToken).getResponse().getStatus()).isEqualTo(200);
        ps.personTokenLedger()
                .recordIssued(new PersonTokenLedger.Issued(
                        "pt-cascade", AGENT_ID, "user", RESOURCE.origin(), "sub", inOneHour()));

        MvcResult result = revokeAsAgentProvider(Jwts.parse(agentToken).claim("jti"));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(result.getResponse().getContentAsByteArray()).isEmpty();
        assertThat(result.getResponse().getContentType()).isNull();
        assertThat(RESOURCE.received())
                .anySatisfy(received -> assertThat(received.json()).containsEntry("jti", "pt-cascade"));
        assertThat(ps.revocations().isRevoked(PS_ORIGIN, "pt-cascade")).isTrue();
        assertSignatureError(agentRequest(agentToken), "revoked_jwt");
    }

    @Test
    void resourceRevokesItsOwnResourceToken() throws Exception {
        MvcResult result = revokeAsResource(revocation("rt-1"), RS_KEY);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(ps.revocations().isRevoked(RESOURCE.origin(), "rt-1")).isTrue();
        assertThat(ps.revocations().isRevoked(PS_ORIGIN, "rt-1")).isFalse();
    }

    @Test
    void unsignedRequestIsInvalidSignature() throws Exception {
        MvcResult result = mvc.perform(
                        post(REQUEST_BASE + "/revoke").contentType(JSON_UTF8).content(revocation("rt-1")))
                .andReturn();
        assertSignatureError(result, "invalid_signature");
    }

    @Test
    void otherSchemesAreUnsupportedAndNameJwksUri() throws Exception {
        MvcResult result = send("/revoke", revocation("rt-1"), RS_KEY, new SignatureScheme.Hwk(), BODY_COMPONENTS);
        assertSignatureError(result, "unsupported_scheme");
        assertThat(result.getResponse().getHeader("Accept-Signature-Scheme")).isEqualTo("jwks_uri");
    }

    @Test
    void wrongKeyIsInvalidSignature() throws Exception {
        assertSignatureError(revokeAsResource(revocation("rt-wrong-key"), STRANGER_KEY), "invalid_signature");
        assertThat(ps.revocations().isRevoked(RESOURCE.origin(), "rt-wrong-key"))
                .isFalse();
    }

    @Test
    void unresolvableIssuerKeysAreUnknownKey() throws Exception {
        ps.revocations().recordResourceIssuer("https://unknown-rs.example");
        MvcResult result = send(
                "/revoke",
                revocation("rt-1"),
                RS_KEY,
                new SignatureScheme.JwksUri("https://unknown-rs.example", "aauth-resource.json", "rs-kid"),
                BODY_COMPONENTS);
        assertSignatureError(result, "unknown_key");
    }

    @Test
    void untrustedAgentProvidersAreUnsupportedIss() throws Exception {
        MvcResult result = send(
                "/revoke",
                revocation("a-1"),
                STRANGER_KEY,
                new SignatureScheme.JwksUri("https://stranger-ap.example", "aauth-agent.json", "k"),
                BODY_COMPONENTS);
        assertProblem(result, 403, "unsupported_iss");
        assertThat(result.getResponse().getHeader("Signature-Error")).isNull();
    }

    @Test
    void otherServerTypesAreUnsupportedIss() throws Exception {
        MvcResult result = send(
                "/revoke",
                revocation("a-1"),
                RS_KEY,
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-access.json", "rs-kid"),
                BODY_COMPONENTS);
        assertProblem(result, 403, "unsupported_iss");
    }

    @Test
    void bodyMustBeCovered() throws Exception {
        MvcResult result = send(
                "/revoke",
                revocation("rt-1"),
                RS_KEY,
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-resource.json", "rs-kid"),
                List.of());
        assertSignatureError(result, "invalid_input");
    }

    @Test
    void jtiAndExpAreRequired() throws Exception {
        for (Map<String, Object> body : List.<Map<String, Object>>of(
                Map.of("jti", "rt-1"),
                Map.of("exp", inOneHour()),
                Map.of("jti", "", "exp", inOneHour()),
                Map.of("jti", "rt-1", "exp", "soon"),
                Map.of("jti", "rt-1", "exp", 1.5))) {
            byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
            assertProblem(revokeAsResource(bytes, RS_KEY), 400, "invalid_request");
        }
        assertProblem(revokeAsResource("[1]".getBytes(StandardCharsets.UTF_8), RS_KEY), 400, "invalid_request");
    }

    @Test
    void signatureCreatedAheadOfTheClockIsClockSkew() throws Exception {
        MvcResult result = send(
                "/revoke",
                revocation("rt-ahead"),
                RS_KEY,
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-resource.json", "rs-kid"),
                BODY_COMPONENTS,
                Instant.now().getEpochSecond() + 300);
        assertSignatureError(result, "clock_skew");
        assertThat(ps.revocations().isRevoked(RESOURCE.origin(), "rt-ahead")).isFalse();
    }

    @Test
    void aResourceThisPsHoldsNoTokensFromIsUnsupportedIssBeforeAnyFetch() throws Exception {
        MvcResult result = send(
                "/revoke",
                revocation("rt-1"),
                RS_KEY,
                new SignatureScheme.JwksUri("https://internal.example", "aauth-resource.json", "rs-kid"),
                BODY_COMPONENTS);
        assertProblem(result, 403, "unsupported_iss");
    }

    @Test
    void aCascadeOutlastingTheHoldIsDeferredAndOnlyItsCallerMayPoll() throws Exception {
        String agentId = "aauth:deferred@agent-server.example";
        ps.revocations().recordAgentToken(PS_ORIGIN, "agent-jti-deferred", agentId, inOneHour());
        ps.personTokenLedger()
                .recordIssued(new PersonTokenLedger.Issued(
                        "pt-deferred", agentId, "user", SLOW_RESOURCE.origin(), "sub", inOneHour()));

        MvcResult accepted = revokeWithoutWaiting(revocation("agent-jti-deferred"), AS_KEY, AS_IDENTITY);

        assertThat(accepted.getResponse().getStatus()).isEqualTo(202);
        assertThat(accepted.getResponse().getHeader("Retry-After")).isEqualTo("0");
        assertThat(accepted.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(json(accepted)).containsEntry("status", "pending");
        String location = accepted.getResponse().getHeader("Location");
        assertThat(location).startsWith(PS_ORIGIN + "/revoke/pending/");

        SignatureScheme resourceIdentity =
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-resource.json", "rs-kid");
        assertThat(poll(location, RS_KEY, resourceIdentity).getResponse().getStatus())
                .isEqualTo(404);

        MvcResult done = poll(location, AS_KEY, AS_IDENTITY);
        assertThat(done.getResponse().getStatus()).isEqualTo(200);
        assertThat(done.getResponse().getContentAsByteArray()).isEmpty();
        assertThat(SLOW_RESOURCE.received())
                .anySatisfy(received -> assertThat(received.json()).containsEntry("jti", "pt-deferred"));
        assertThat(poll(location, AS_KEY, AS_IDENTITY).getResponse().getStatus())
                .isEqualTo(404);
    }

    @Test
    void anUnknownPendingRevocationIsNotFound() throws Exception {
        MvcResult result = poll(PS_ORIGIN + "/revoke/pending/nope", AS_KEY, AS_IDENTITY);
        assertThat(result.getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void aRevocationWithNothingDownstreamNeverAnswers202() throws Exception {
        MvcResult result = revokeWithoutWaiting(
                revocation("rt-no-wait"),
                RS_KEY,
                new SignatureScheme.JwksUri(RESOURCE.origin(), "aauth-resource.json", "rs-kid"));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
    }
}
