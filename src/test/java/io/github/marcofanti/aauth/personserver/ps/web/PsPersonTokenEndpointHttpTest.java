package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.AgentTokenForge;
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
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
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
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Draft-11 person token endpoint (§7.1) over HTTP, secure mode. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class PsPersonTokenEndpointHttpTest {

    private static final String PS_ORIGIN = "https://ps.example";
    // MockMvc gives an absolute URL without a port the default port 80; name 443 explicitly.
    private static final String REQUEST_BASE = PS_ORIGIN + ":443";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String AGENT_ID = "aauth:planner.7f3c@agent-server.example";
    private static final String RESOURCE = "https://rs.example";

    private static final KeyPair AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair OTHER_AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AS_KEY = KeyPairs.generateEd25519();

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
                    .build());
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    private static String agentToken(String sub, KeyPair key, long exp, String parentAgent) {
        if (parentAgent != null) {
            // Forged: the library refuses to mint a sub-agent token for a parent it did not verify.
            return AgentTokenForge.sign(
                    PS_ORIGIN, sub, jwk(key, "eph"), AS_KEY.getPrivate(), "as-kid", exp, parentAgent);
        }
        return AgentTokens.create(
                AgentTokens.Spec.builder(PS_ORIGIN, sub, jwk(key, "eph"), AS_KEY.getPrivate(), "as-kid")
                        .exp(exp)
                        .build());
    }

    private static String agentToken() {
        return agentToken(AGENT_ID, AGENT_KEY, Instant.now().getEpochSecond() + 3600, null);
    }

    private MockHttpServletRequestBuilder signed(String method, String path, byte[] body, KeyPair key, String token) {
        SignRequest.Builder spec = SignRequest.builder(method, PS_ORIGIN + path)
                .headers(
                        body == null
                                ? Map.of("Host", "ps.example")
                                : Map.of("Host", "ps.example", "Content-Type", JSON_UTF8))
                .keyPair(key)
                .scheme(new SignatureScheme.Jwt(token));
        if (body != null) {
            spec.body(body).additionalComponents(BODY_COMPONENTS);
        }
        Map<String, String> headers = RequestSigner.sign(spec.build());
        MockHttpServletRequestBuilder request =
                "GET".equals(method) ? get(REQUEST_BASE + path) : post(REQUEST_BASE + path);
        if (body != null) {
            request.contentType(JSON_UTF8).content(body);
        }
        headers.forEach(request::header);
        return request;
    }

    private MvcResult requestPersonToken(Map<String, Object> params, KeyPair key, String token) throws Exception {
        byte[] body = Json.write(params).getBytes(StandardCharsets.UTF_8);
        return mvc.perform(signed("POST", "/person-token", body, key, token)).andReturn();
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    /** Ask, approve on the consent page, poll — returns the issued person token. */
    private String approveFirstUse() throws Exception {
        MvcResult deferred = requestPersonToken(
                Map.of("resource", RESOURCE, "capabilities", List.of("interaction")), AGENT_KEY, agentToken());
        assertThat(deferred.getResponse().getStatus()).isEqualTo(202);
        Map<String, Object> pending = json(deferred);
        String code = (String) pending.get("code");
        String pendingId = (String) pending.get("pending_id");

        mvc.perform(get(REQUEST_BASE + "/consent").param("code", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pending_kind").value("person_token"))
                .andExpect(jsonPath("$.resource_iss").value(RESOURCE));
        mvc.perform(post(REQUEST_BASE + "/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"approved\":true}"))
                .andExpect(status().isOk());

        MvcResult polled = mvc.perform(signed("GET", "/pending/" + pendingId, null, AGENT_KEY, agentToken()))
                .andExpect(status().isOk())
                .andReturn();
        return (String) json(polled).get("person_token");
    }

    @Test
    void bodyWithoutContentCoverageIsRejected() throws Exception {
        // §11.3.3 (PS-101): a body must be covered by content-digest and content-type.
        byte[] body = Json.write(Map.of("resource", RESOURCE)).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + "/person-token")
                .headers(Map.of("Host", "ps.example", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(AGENT_KEY)
                .scheme(new SignatureScheme.Jwt(agentToken()))
                .build());
        MockHttpServletRequestBuilder request =
                post(REQUEST_BASE + "/person-token").contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        mvc.perform(request)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Signature-Error", "error=invalid_input"));
    }

    @Test
    void bodyAlteredAfterSigningIsRejected() throws Exception {
        byte[] signedBody = Json.write(Map.of("resource", RESOURCE)).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + "/person-token")
                .headers(Map.of("Host", "ps.example", "Content-Type", JSON_UTF8))
                .body(signedBody)
                .keyPair(AGENT_KEY)
                .scheme(new SignatureScheme.Jwt(agentToken()))
                .additionalComponents(BODY_COMPONENTS)
                .build());
        byte[] tampered = Json.write(Map.of("resource", "https://evil.example")).getBytes(StandardCharsets.UTF_8);
        MockHttpServletRequestBuilder request =
                post(REQUEST_BASE + "/person-token").contentType(JSON_UTF8).content(tampered);
        headers.forEach(request::header);
        mvc.perform(request)
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("Signature-Error", "error=invalid_signature"));
    }

    @Test
    void firstUseWithoutInteractionCapabilityIsUserUnreachable() throws Exception {
        mvc.perform(signed(
                        "POST",
                        "/person-token",
                        Json.write(Map.of("resource", RESOURCE)).getBytes(StandardCharsets.UTF_8),
                        AGENT_KEY,
                        agentToken()))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.error").value("user_unreachable"));
    }

    @Test
    void approvedFirstUseIssuesADraft11PersonToken() throws Exception {
        String token = approveFirstUse();

        Map<String, Object> claims = PersonTokens.verify(
                token,
                (id, dwk, kid) -> ps.psSigning().getJwks(),
                TokenVerifier.Options.forType(null).withAudience(RESOURCE));
        assertThat(claims)
                .containsEntry("iss", PS_ORIGIN)
                .containsEntry("aud", RESOURCE)
                .containsEntry("dwk", "aauth-person.json")
                .doesNotContainKeys("scope", "account", "agent", "act");
        assertThat(Jwts.parse(token).header()).containsEntry("typ", "aa-person+jwt");
        assertThat(((Map<?, ?>) claims.get("cnf")).get("jwk")).isEqualTo(jwk(AGENT_KEY, "eph"));
        long iat = ((Number) claims.get("iat")).longValue();
        long exp = ((Number) claims.get("exp")).longValue();
        assertThat(exp - iat).isLessThanOrEqualTo(3600);
    }

    @Test
    void approvedResourceIssuesImmediatelyWithAStableDirectedSub() throws Exception {
        String first = approveFirstUse();

        MvcResult again = requestPersonToken(Map.of("resource", RESOURCE), AGENT_KEY, agentToken());
        assertThat(again.getResponse().getStatus()).isEqualTo(200);
        String second = (String) json(again).get("person_token");

        String otherAgent = "aauth:mailer.91aa@agent-server.example";
        MvcResult other = requestPersonToken(
                Map.of("resource", RESOURCE),
                OTHER_AGENT_KEY,
                agentToken(otherAgent, OTHER_AGENT_KEY, Instant.now().getEpochSecond() + 3600, null));
        assertThat(other.getResponse().getStatus()).isEqualTo(200);
        String third = (String) json(other).get("person_token");

        // §14.1: same person at the same resource → same sub, whichever agent or key asks.
        String sub = Jwts.parse(first).claim("sub");
        assertThat(Jwts.parse(second).claim("sub")).isEqualTo(sub);
        assertThat(Jwts.parse(third).claim("sub")).isEqualTo(sub);
    }

    @Test
    void personTokenNeverOutlivesTheAgentToken() throws Exception {
        approveFirstUse();
        long agentExp = Instant.now().getEpochSecond() + 120;
        MvcResult result = requestPersonToken(
                Map.of("resource", RESOURCE), AGENT_KEY, agentToken(AGENT_ID, AGENT_KEY, agentExp, null));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(Jwts.parse((String) json(result).get("person_token")).numericClaim("exp"))
                .isLessThanOrEqualTo(agentExp);
    }

    @Test
    void invalidResourceIsInvalidRequest() throws Exception {
        MvcResult result = requestPersonToken(Map.of("resource", "not a url"), AGENT_KEY, agentToken());
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(json(result)).containsEntry("error", "invalid_request");
    }

    @Test
    void unknownMissionIsInvalidRequest() throws Exception {
        MvcResult result = requestPersonToken(
                Map.of("resource", RESOURCE, "mission_s256", "no-such-mission"), AGENT_KEY, agentToken());
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(json(result)).containsEntry("error", "invalid_request");
    }

    @Test
    void subagentTokenNamingAnotherParentIsRejected() throws Exception {
        String subagent = agentToken(
                "aauth:planner.7f3c+search1@agent-server.example",
                OTHER_AGENT_KEY,
                Instant.now().getEpochSecond() + 3600,
                "aauth:someone.else@agent-server.example");
        MvcResult result =
                requestPersonToken(Map.of("resource", RESOURCE, "subagent_token", subagent), AGENT_KEY, agentToken());
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(json(result)).containsEntry("error", "invalid_subagent_token");
    }

    @Test
    void subagentPersonTokenBindsTheSubagentKey() throws Exception {
        approveFirstUse();
        String subagent = agentToken(
                "aauth:planner.7f3c+search1@agent-server.example",
                OTHER_AGENT_KEY,
                Instant.now().getEpochSecond() + 3600,
                AGENT_ID);
        MvcResult result =
                requestPersonToken(Map.of("resource", RESOURCE, "subagent_token", subagent), AGENT_KEY, agentToken());
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        Map<String, Object> claims =
                Jwts.parse((String) json(result).get("person_token")).payload();
        assertThat(((Map<?, ?>) claims.get("cnf")).get("jwk")).isEqualTo(jwk(OTHER_AGENT_KEY, "eph"));
    }

    @Test
    void aRevokedSubagentTokenIsRevokedAndAnAcceptedOneIsRecorded() throws Exception {
        approveFirstUse();
        String sub = "aauth:planner.7f3c+search2@agent-server.example";
        String subagent = agentToken(sub, OTHER_AGENT_KEY, Instant.now().getEpochSecond() + 3600, AGENT_ID);
        String jti = Jwts.parse(subagent).claim("jti");

        MvcResult accepted =
                requestPersonToken(Map.of("resource", RESOURCE, "subagent_token", subagent), AGENT_KEY, agentToken());
        assertThat(accepted.getResponse().getStatus()).isEqualTo(200);
        assertThat(ps.revocations().agentSub(PS_ORIGIN, jti)).isEqualTo(sub);

        ps.revocations().revoke(PS_ORIGIN, jti, Instant.now().getEpochSecond() + 3600);
        MvcResult refused =
                requestPersonToken(Map.of("resource", RESOURCE, "subagent_token", subagent), AGENT_KEY, agentToken());
        assertThat(refused.getResponse().getStatus()).isEqualTo(400);
        assertThat(json(refused)).containsEntry("error", ProblemError.REVOKED_SUBAGENT_TOKEN);
    }
}
