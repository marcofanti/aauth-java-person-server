package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Port of {@code tests/test_ps_token_endpoint.py} — mode-3 secure {@code POST /token} over HTTP. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsTokenEndpointHttpTest {

    // MockMvc reconstructs request URLs as http://localhost, so the PS origin must match
    // for RFC 9421 @authority coverage and agent-token iss checks.
    private static final String PS_ORIGIN = "http://localhost";
    private static final String RESOURCE_ISS = "https://rs.example";
    private static final String AGENT_ID = "mode3-test-agent";

    private static final KeyPair EPHEMERAL_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AS_KEY = KeyPairs.generateEd25519();
    private static final KeyPair RS_KEY = KeyPairs.generateEd25519();

    private static Map<String, Object> signingJwk(KeyPair keyPair, String kid) {
        Map<String, Object> jwk = new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), kid));
        jwk.put("use", "sig");
        return jwk;
    }

    private static Map<String, Object> jwksOf(KeyPair keyPair, String kid) {
        return Map.of("keys", List.of(signingJwk(keyPair, kid)));
    }

    @TestConfiguration
    static class Config {
        @Bean
        PsSettings psSettings() {
            boolean autoApprove = Boolean.parseBoolean(System.getProperty("mode3.autoApprove", "false"));
            return new PsSettings(
                    PS_ORIGIN,
                    false,
                    null,
                    null,
                    "user",
                    autoApprove,
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
        PsContainer psContainer(PsSettings settings) {
            return PsWiring.buildMemoryPs(PsWiring.Options.builder(settings.origin())
                    .autoApproveToken(settings.autoApproveToken())
                    .insecureDev(false)
                    .signingKeyPath(null)
                    .trustFile(null)
                    .consentScopesFile(null)
                    .selfJwksProvider(() -> jwksOf(AS_KEY, "as-kid"))
                    .resourceJwks(
                            iss -> RESOURCE_ISS.equals(iss.replaceAll("/+$", "")) ? jwksOf(RS_KEY, "rs-kid") : null)
                    .build());
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    private static String agentJwt(String iss) {
        return AgentTokens.create(
                AgentTokens.Spec.builder(iss, AGENT_ID, signingJwk(EPHEMERAL_KEY, "eph"), AS_KEY.getPrivate(), "as-kid")
                        .exp(Instant.now().getEpochSecond() + 3600)
                        .build());
    }

    private static String agentJkt() {
        return Jwk.thumbprint(signingJwk(EPHEMERAL_KEY, "eph"));
    }

    private static String resourceJwt(String scope, String aud) {
        return ResourceTokens.create(new ResourceTokens.Spec(
                RESOURCE_ISS,
                aud,
                AGENT_ID,
                agentJkt(),
                scope,
                RS_KEY.getPrivate(),
                "rs-kid",
                Instant.now().getEpochSecond() + 3600,
                null,
                null));
    }

    private MockHttpServletRequestBuilder signedTokenPost(String resourceToken, String agentToken) {
        byte[] body = Json.write(Map.of("resource_token", resourceToken)).getBytes(StandardCharsets.UTF_8);
        Map<String, String> signedHeaders = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + "/token")
                .headers(Map.of("Host", "localhost", "Content-Type", "application/json"))
                .body(body)
                .keyPair(EPHEMERAL_KEY)
                .scheme(new SignatureScheme.Jwt(agentToken))
                .build());
        MockHttpServletRequestBuilder request =
                post("/token").contentType("application/json").content(body);
        signedHeaders.forEach(request::header);
        return request;
    }

    @Test
    void mode3PostTokenIssuesRealAuthJwt() throws Exception {
        MvcResult result = mvc.perform(signedTokenPost(resourceJwt("demo.scope", PS_ORIGIN), agentJwt(PS_ORIGIN)))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> body = Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String authToken = (String) body.get("auth_token");
        assertThat(authToken).startsWith("eyJ");

        @SuppressWarnings("unchecked")
        Map<String, Object> claims =
                (Map<String, Object>) AuthTokens.parseTokenClaims(authToken).get("payload");
        assertThat(claims).containsEntry("iss", PS_ORIGIN);
        assertThat(claims).containsEntry("aud", RESOURCE_ISS);
        assertThat(claims).containsEntry("agent", AGENT_ID);
        assertThat(claims).containsEntry("sub", "user");
        assertThat(claims).containsEntry("scope", "demo.scope");
        assertThat(claims).containsEntry("dwk", "aauth-person.json");
        assertThat(claims.get("act")).isEqualTo(Map.of("sub", AGENT_ID));

        // Full verification against the PS's own JWKS (kid + Ed25519 signature + audience).
        Map<String, Object> verified = AuthTokens.verifyToken(
                authToken, iss -> ps.psSigning().getJwks(), AuthTokens.VerifyOptions.forType(AuthTokens.TYPE));
        assertThat(verified).containsEntry("aud", RESOURCE_ISS);
    }

    @Test
    void mode3UnknownAgentIssuerReturnsInvalidAgentToken() throws Exception {
        mvc.perform(signedTokenPost(
                        resourceJwt("demo.scope", PS_ORIGIN), agentJwt("https://unknown-agent-issuer.example")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_agent_token"));
    }

    @Test
    void mode3TamperedResourceTokenRejected() throws Exception {
        String tampered = resourceJwt("demo.scope", PS_ORIGIN);
        tampered = tampered.substring(0, tampered.length() - 4) + "xxxx";
        mvc.perform(signedTokenPost(tampered, agentJwt(PS_ORIGIN)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_resource_token"));
    }

    @Test
    void mode3IssuesWithoutConsentWhenScopeOmitsRequireUser() throws Exception {
        mvc.perform(signedTokenPost(resourceJwt("read:calendar", PS_ORIGIN), agentJwt(PS_ORIGIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.auth_token").exists());
    }

    @Test
    void mode3DefersForConsentWhenScopeIncludesRequireUser() throws Exception {
        mvc.perform(signedTokenPost(resourceJwt("read:profile require:user", PS_ORIGIN), agentJwt(PS_ORIGIN)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("pending"));
    }

    @Test
    void fourPartyAudNotPsStillFakeFederator() throws Exception {
        mvc.perform(signedTokenPost(
                        resourceJwt("demo.scope", "https://other-resource-party.example"), agentJwt(PS_ORIGIN)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.auth_token").value(org.hamcrest.Matchers.startsWith("aa-auth.fake.")));
    }

    @Test
    void missingSignatureHeadersRejectedWithInvalidSignature() throws Exception {
        mvc.perform(post("/token").contentType("application/json").content(Json.write(Map.of("resource_token", "x"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
    }
}
