package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
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

    private static final String PS_ORIGIN = "http://localhost";
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
        AgentTokens.Spec.Builder builder = AgentTokens.Spec.builder(
                        PS_ORIGIN, sub, jwk(key, "eph"), AS_KEY.getPrivate(), "as-kid")
                .exp(exp);
        if (parentAgent != null) {
            builder.parentAgent(parentAgent);
        }
        return AgentTokens.create(builder.build());
    }

    private static String agentToken() {
        return agentToken(AGENT_ID, AGENT_KEY, Instant.now().getEpochSecond() + 3600, null);
    }

    private MockHttpServletRequestBuilder signed(String method, String path, byte[] body, KeyPair key, String token) {
        SignRequest.Builder spec = SignRequest.builder(method, PS_ORIGIN + path)
                .headers(
                        body == null
                                ? Map.of("Host", "localhost")
                                : Map.of("Host", "localhost", "Content-Type", "application/json"))
                .keyPair(key)
                .scheme(new SignatureScheme.Jwt(token));
        if (body != null) {
            spec.body(body);
        }
        Map<String, String> headers = RequestSigner.sign(spec.build());
        MockHttpServletRequestBuilder request = "GET".equals(method) ? get(path) : post(path);
        if (body != null) {
            request.contentType("application/json").content(body);
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

        mvc.perform(get("/consent").param("code", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pending_kind").value("person_token"))
                .andExpect(jsonPath("$.resource_iss").value(RESOURCE));
        mvc.perform(post("/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"approved\":true}"))
                .andExpect(status().isOk());

        MvcResult polled = mvc.perform(signed("GET", "/pending/" + pendingId, null, AGENT_KEY, agentToken()))
                .andExpect(status().isOk())
                .andReturn();
        return (String) json(polled).get("person_token");
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

        Map<String, Object> claims =
                PersonTokens.verify(token, iss -> ps.psSigning().getJwks(), RESOURCE);
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
}
