package io.github.marcofanti.aauth.personserver.portal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.web.AsSettings;
import io.github.marcofanti.aauth.personserver.ps.DeferredAgentSelfJwks;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.web.PsSettings;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Unified portal (default profile): merged JWKS, portal-aligned AS metadata, the
 * {@code /register/pending} path split, cross-token admin auth, and the full all-Java flow —
 * agent registers, person approves, the portal-issued agent token signs a secure
 * {@code POST /token}, and the PS returns a real {@code aa-auth+jwt}.
 */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PortalHttpTest {

    private static final String ORIGIN = "http://localhost";
    private static final String RESOURCE_ISS = "https://rs.example";
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();

    @TestConfiguration
    static class Config {
        @Bean
        PsSettings psSettings() {
            return new PsSettings(
                    ORIGIN,
                    false,
                    "mytoken",
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
                    null);
        }

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
                    "AAuth Person Portal",
                    "mytoken",
                    null,
                    false);
        }

        @Bean
        PsContainer psContainer(PsSettings settings, DeferredAgentSelfJwks deferredAgentSelfJwks) {
            return PsWiring.buildMemoryPs(PsWiring.Options.builder(settings.origin())
                    .insecureDev(false)
                    .signingKeyPath(null)
                    .trustFile(null)
                    .consentScopesFile(null)
                    .selfJwksProvider(deferredAgentSelfJwks)
                    .resourceJwks(iss -> RESOURCE_ISS.equals(iss.replaceAll("/+$", ""))
                            ? Map.of("keys", List.of(Jwk.publicKeyToJwk(RS_KEY.getPublic(), "rs-kid")))
                            : null)
                    .build());
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    @Autowired
    private AsContainer as;

    private static Map<String, Object> publicJwk(KeyPair keyPair) {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), null));
    }

    private MockHttpServletRequestBuilder signed(
            String method, String path, byte[] body, KeyPair keyPair, SignatureScheme scheme) {
        Map<String, String> signedHeaders = RequestSigner.sign(SignRequest.builder(method, ORIGIN + path)
                .headers(
                        body == null
                                ? Map.of("Host", "localhost")
                                : Map.of("Host", "localhost", "Content-Type", "application/json"))
                .body(body)
                .keyPair(keyPair)
                .scheme(scheme)
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

    @Test
    void mergedJwksContainsPsAndAsKeys() throws Exception {
        MvcResult result = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> jwks = Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        List<?> keys = (List<?>) jwks.get("keys");
        List<String> kids = keys.stream()
                .map(key -> String.valueOf(((Map<?, ?>) key).get("kid")))
                .toList();
        assertThat(kids).contains(ps.psSigning().kid(), as.signing().kid());
    }

    @Test
    void portalMetadataAlignsBothServersToOneOrigin() throws Exception {
        mvc.perform(get("/.well-known/aauth-person.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ORIGIN))
                .andExpect(jsonPath("$.token_endpoint").value(ORIGIN + "/token"));
        mvc.perform(get("/.well-known/aauth-agent.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ORIGIN))
                .andExpect(jsonPath("$.client_name").value("AAuth Person Portal"))
                .andExpect(jsonPath("$.registration_endpoint").value(ORIGIN + "/register"));
    }

    @Test
    void portalUiIsServed() throws Exception {
        mvc.perform(get("/ui/index.html")).andExpect(status().isOk());
        mvc.perform(get("/ui/portal.html")).andExpect(status().isOk());
        mvc.perform(get("/ui/consent.html")).andExpect(status().isOk());
    }

    @Test
    void issuedTokensRouteRequiresAdminAndReturnsList() throws Exception {
        mvc.perform(get("/admin/issued-tokens")).andExpect(status().isUnauthorized());
        mvc.perform(get("/admin/issued-tokens").header("Authorization", "Bearer wrong"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/admin/issued-tokens").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    void adminRoutesAcceptPersonTokenAndPersonRoutesAcceptAdminToken() throws Exception {
        mvc.perform(get("/missions").header("Authorization", "Bearer mytoken")).andExpect(status().isOk());
        mvc.perform(get("/person/registrations").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk());
        mvc.perform(get("/person/bindings").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk());
        mvc.perform(get("/user/missions").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk());
    }

    @Test
    void fullAllJavaFlowFromRegistrationToAuthToken() throws Exception {
        KeyPair stableKey = KeyPairs.generateEd25519();
        KeyPair ephemeralKey = KeyPairs.generateEd25519();

        // 1. Register (hwk-signed) → 202 with the portal's /register/pending path.
        Map<String, Object> registerBody = new LinkedHashMap<>();
        registerBody.put("stable_pub", publicJwk(stableKey));
        registerBody.put("agent_name", "Portal Flow Agent");
        byte[] registerBytes = Json.write(registerBody).getBytes(StandardCharsets.UTF_8);
        MvcResult registered = mvc.perform(
                        signed("POST", "/register", registerBytes, ephemeralKey, new SignatureScheme.Hwk()))
                .andExpect(status().isAccepted())
                .andReturn();
        String location = registered.getResponse().getHeader("Location");
        assertThat(location).startsWith("/register/pending/");
        String pendingId = location.substring("/register/pending/".length());

        // 2. Poll before approval → 202 pending on the portal path.
        mvc.perform(signed("GET", "/register/pending/" + pendingId, null, ephemeralKey, new SignatureScheme.Hwk()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("pending"));

        // 3. Person approves; agent polls its aa-agent+jwt.
        mvc.perform(post("/person/registrations/" + pendingId + "/approve").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk());
        MvcResult polled = mvc.perform(
                        signed("GET", "/register/pending/" + pendingId, null, ephemeralKey, new SignatureScheme.Hwk()))
                .andExpect(status().isOk())
                .andReturn();
        String agentToken = (String) Json.readMap(polled.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("agent_token");
        String agentId = String.valueOf(io.github.marcofanti.aauth.signing.Jwts.parse(agentToken)
                .payload()
                .get("sub"));

        // 4. Use the agent token to sign a secure POST /token with a resource token aud=portal.
        String agentJkt = Jwk.thumbprint(publicJwk(ephemeralKey));
        String resourceToken = ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE_ISS,
                ORIGIN,
                agentId,
                agentJkt,
                "demo.scope",
                RS_KEY.getPrivate(),
                "rs-kid",
                Instant.now().getEpochSecond() + 3600,
                null,
                null));
        byte[] tokenBytes = Json.write(Map.of("resource_token", resourceToken)).getBytes(StandardCharsets.UTF_8);
        MvcResult issued = mvc.perform(
                        signed("POST", "/token", tokenBytes, ephemeralKey, new SignatureScheme.Jwt(agentToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.auth_token").exists())
                .andReturn();
        String authToken = (String) Json.readMap(issued.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("auth_token");
        assertThat(authToken).startsWith("eyJ");
        Map<String, Object> claims =
                io.github.marcofanti.aauth.signing.Jwts.parse(authToken).payload();
        assertThat(claims).containsEntry("iss", ORIGIN);
        assertThat(claims).containsEntry("aud", RESOURCE_ISS);
        assertThat(claims).containsEntry("agent", agentId);

        // 5. The issuance is visible on the portal's admin issued-tokens route.
        mvc.perform(get("/admin/issued-tokens").header("Authorization", "Bearer mytoken"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].agent_id").value(agentId))
                .andExpect(jsonPath("$[0].resource_iss").value(RESOURCE_ISS))
                .andExpect(jsonPath("$[0].token_jti").exists());
    }

    @Test
    void psOwnsPendingPathOnPortal() throws Exception {
        // /pending/{id} on the portal is the PS consent poll — unknown ids give the PS 404
        // body, and the AS standalone poll route is not mapped.
        mvc.perform(get("/pending/unknown-id").header("X-AAuth-Agent-Id", "x")).andExpect(status().isUnauthorized());
    }
}
