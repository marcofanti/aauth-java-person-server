package io.github.marcofanti.aauth.personserver.agentserver.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Standalone Agent Server flows with real HTTP message signatures: register → approve →
 * poll → token, re-registration, jkt-jwt refresh, denial, revocation, and the
 * {@code agent_name} validation cases from {@code tests/test_agent_server_register.py}.
 */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
@ActiveProfiles("agent-server")
class AgentServerHttpTest {

    private static final String ORIGIN = "http://localhost";
    private static final String PERSON_TOKEN = "person-secret";

    @TestConfiguration
    static class Config {
        @Bean
        AsSettings asSettings() {
            return new AsSettings(
                    ORIGIN,
                    "localhost",
                    ORIGIN,
                    null,
                    null,
                    86400,
                    3600,
                    60,
                    "AAuth Agent Server",
                    PERSON_TOKEN,
                    null,
                    false);
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private AsContainer container;

    private static Map<String, Object> publicJwk(KeyPair keyPair) {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), null));
    }

    private MockHttpServletRequestBuilder signedHwk(String method, String path, byte[] body, KeyPair ephemeralKey) {
        Map<String, String> signedHeaders = RequestSigner.sign(SignRequest.builder(method, ORIGIN + path)
                .headers(
                        body == null
                                ? Map.of("Host", "localhost")
                                : Map.of("Host", "localhost", "Content-Type", "application/json"))
                .body(body)
                .keyPair(ephemeralKey)
                .scheme(new SignatureScheme.Hwk())
                .build());
        MockHttpServletRequestBuilder request = "GET".equals(method) ? get(path) : post(path);
        if (body != null) {
            request = request.contentType("application/json").content(body);
        }
        for (Map.Entry<String, String> entry : signedHeaders.entrySet()) {
            request = request.header(entry.getKey(), entry.getValue());
        }
        return request;
    }

    private static byte[] registerBody(KeyPair stableKey, String agentName) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stable_pub", publicJwk(stableKey));
        body.put("agent_name", agentName);
        return Json.write(body).getBytes(StandardCharsets.UTF_8);
    }

    private String register202(KeyPair stableKey, KeyPair ephemeralKey, String agentName) throws Exception {
        MvcResult result = mvc.perform(signedHwk("POST", "/register", registerBody(stableKey, agentName), ephemeralKey))
                .andExpect(status().isAccepted())
                .andExpect(header().string("Retry-After", "5"))
                .andExpect(jsonPath("$.status").value("pending"))
                .andExpect(jsonPath("$.expires_at").exists())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).startsWith("/pending/");
        return location.substring("/pending/".length());
    }

    @Test
    void fullRegistrationApprovalFlowIssuesAgentToken() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        String pendingId = register202(stableKey, ephemeralKey, "Test Agent");

        mvc.perform(signedHwk("GET", "/pending/" + pendingId, null, ephemeralKey))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("pending"));

        mvc.perform(get("/person/registrations").header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$[?(@.id == '" + pendingId + "')].agent_name").value("Test Agent"));

        MvcResult approval = mvc.perform(post("/person/registrations/" + pendingId + "/approve")
                        .header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agent_id").exists())
                .andReturn();
        Map<String, Object> approved = Json.readMap(approval.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String agentId = (String) approved.get("agent_id");
        assertThat(agentId).startsWith("aauth:").endsWith("@localhost");

        MvcResult polled = mvc.perform(signedHwk("GET", "/pending/" + pendingId, null, ephemeralKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agent_token").exists())
                .andReturn();
        String agentToken = (String) Json.readMap(polled.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("agent_token");

        Map<String, Object> payload = Jwts.parse(agentToken).payload();
        assertThat(payload).containsEntry("iss", ORIGIN);
        assertThat(payload).containsEntry("sub", agentId);
        assertThat(payload.get("cnf")).isEqualTo(Map.of("jwk", publicJwk(ephemeralKey)));

        // Re-registration with the same stable key issues a token immediately (200, not 202).
        KeyPair newEphemeral = KeyPairs.generateEd25519();
        mvc.perform(signedHwk("POST", "/register", registerBody(stableKey, "Renamed Agent"), newEphemeral))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agent_token").exists());

        mvc.perform(get("/person/bindings").header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.agent_id == '" + agentId + "')].agent_name")
                        .value("Renamed Agent"));
    }

    @Test
    void refreshWithJktJwtRotatesEphemeralKey() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        String pendingId = register202(stableKey, ephemeralKey, "Refresh Agent");
        mvc.perform(post("/person/registrations/" + pendingId + "/approve")
                        .header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk());
        MvcResult polled = mvc.perform(signedHwk("GET", "/pending/" + pendingId, null, ephemeralKey))
                .andExpect(status().isOk())
                .andReturn();
        String firstToken = (String) Json.readMap(polled.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("agent_token");
        String agentId = String.valueOf(Jwts.parse(firstToken).payload().get("sub"));

        // Self-issued jkt-jwt: stable key delegates to a fresh ephemeral key.
        KeyPair rotatedKey = KeyPairs.generateEd25519();
        Map<String, Object> stableJwk = publicJwk(stableKey);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", "jkt-s256+jwt");
        header.put("alg", "Ed25519");
        header.put("jwk", stableJwk);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", "urn:jkt:sha-256:" + Jwk.thumbprint(stableJwk));
        payload.put("iat", Instant.now().getEpochSecond());
        payload.put("exp", Instant.now().getEpochSecond() + 300);
        payload.put("cnf", Map.of("jwk", publicJwk(rotatedKey)));
        String delegationJwt = Jwts.signEdDsa(header, payload, stableKey.getPrivate());

        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> signedHeaders = RequestSigner.sign(SignRequest.builder("POST", ORIGIN + "/refresh")
                .headers(Map.of("Host", "localhost", "Content-Type", "application/json"))
                .body(body)
                .keyPair(rotatedKey)
                .scheme(new SignatureScheme.JktJwt(delegationJwt))
                .build());
        MockHttpServletRequestBuilder request =
                post("/refresh").contentType("application/json").content(body);
        for (Map.Entry<String, String> entry : signedHeaders.entrySet()) {
            request = request.header(entry.getKey(), entry.getValue());
        }
        MvcResult refreshed = mvc.perform(request)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agent_token").exists())
                .andReturn();
        Map<String, Object> refreshedClaims = Jwts.parse(
                        (String) Json.readMap(refreshed.getResponse().getContentAsString(StandardCharsets.UTF_8))
                                .get("agent_token"))
                .payload();
        assertThat(refreshedClaims).containsEntry("sub", agentId);
        assertThat(refreshedClaims.get("cnf")).isEqualTo(Map.of("jwk", publicJwk(rotatedKey)));
    }

    @Test
    void deniedRegistrationReturns403OnPoll() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        String pendingId = register202(stableKey, ephemeralKey, "Denied Agent");
        mvc.perform(post("/person/registrations/" + pendingId + "/deny")
                        .header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk());
        mvc.perform(signedHwk("GET", "/pending/" + pendingId, null, ephemeralKey))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("denied"));
    }

    @Test
    void pollWithDifferentEphemeralKeyIsRejected() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        String pendingId = register202(stableKey, ephemeralKey, "Continuity Agent");
        KeyPair otherKey = KeyPairs.generateEd25519();
        mvc.perform(signedHwk("GET", "/pending/" + pendingId, null, otherKey))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
    }

    @Test
    void agentNameValidationMatchesPythonRules() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        mvc.perform(signedHwk("POST", "/register", registerBody(stableKey, "   "), ephemeralKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        mvc.perform(signedHwk("POST", "/register", registerBody(stableKey, "x".repeat(257)), ephemeralKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        byte[] missingStablePub = Json.write(Map.of("agent_name", "No Key")).getBytes(StandardCharsets.UTF_8);
        mvc.perform(signedHwk("POST", "/register", missingStablePub, ephemeralKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void unsignedRegisterRejected() throws Exception {
        mvc.perform(post("/register")
                        .contentType("application/json")
                        .content(registerBody(KeyPairs.generateEd25519(), "NoSig")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
    }

    @Test
    void personRoutesRequireBearer() throws Exception {
        mvc.perform(get("/person/registrations")).andExpect(status().isUnauthorized());
        mvc.perform(get("/person/bindings").header("Authorization", "Bearer wrong"))
                .andExpect(status().isForbidden());
    }

    @Test
    void createBindingFromStablePubThenRegisterIsImmediate() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        MvcResult created = mvc.perform(post("/person/bindings")
                        .header("Authorization", "Bearer " + PERSON_TOKEN)
                        .contentType("application/json")
                        .content(registerBody(stableKey, "Pre-trusted Agent")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.agent_id").exists())
                .andReturn();
        String agentId = (String) Json.readMap(created.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("agent_id");

        // Duplicate stable key → 409 conflict with the existing agent id.
        mvc.perform(post("/person/bindings")
                        .header("Authorization", "Bearer " + PERSON_TOKEN)
                        .contentType("application/json")
                        .content(registerBody(stableKey, "Duplicate")))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.agent_id").value(agentId));

        KeyPair ephemeralKey = KeyPairs.generateEd25519();
        mvc.perform(signedHwk("POST", "/register", registerBody(stableKey, "Pre-trusted Agent"), ephemeralKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.agent_token").exists());

        // Revoke, then register queues a new pending approval instead of immediate issuance.
        mvc.perform(post("/person/bindings/" + agentId + "/revoke").header("Authorization", "Bearer " + PERSON_TOKEN))
                .andExpect(status().isOk());
        mvc.perform(signedHwk(
                        "POST", "/register", registerBody(stableKey, "Pre-trusted Agent"), KeyPairs.generateEd25519()))
                .andExpect(status().isAccepted());
    }

    @Test
    void wellKnownAgentMetadataAndJwks() throws Exception {
        mvc.perform(get("/.well-known/aauth-agent.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ORIGIN))
                .andExpect(jsonPath("$.registration_endpoint").value(ORIGIN + "/register"))
                .andExpect(jsonPath("$.client_name").value("AAuth Agent Server"));
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(container.signing().kid()));
    }
}
