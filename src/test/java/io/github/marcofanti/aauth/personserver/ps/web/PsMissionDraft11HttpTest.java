package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
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
import java.time.Instant;
import java.util.Base64;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Draft-11 missions (§8) over HTTP: creation, update, completion, endpoint errors. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsMissionDraft11HttpTest {

    private static final String PS_ORIGIN = "http://localhost";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");
    // MockMvc rewrites a bare application/json to this; sign the value it actually sends.
    private static final String JSON_UTF8 = "application/json;charset=UTF-8";
    private static final String AGENT_ID = "aauth:planner.7f3c@agent-server.example";
    private static final String OTHER_AGENT = "aauth:mailer.91aa@agent-server.example";

    private static final KeyPair AGENT_KEY = KeyPairs.generateEd25519();
    private static final KeyPair OTHER_KEY = KeyPairs.generateEd25519();
    private static final KeyPair AS_KEY = KeyPairs.generateEd25519();

    private static Map<String, Object> jwk(KeyPair keyPair) {
        return new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), "eph"));
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
                    86400L);
        }

        @Bean
        PsContainer psContainer(PsSettings settings) {
            return PsWiring.buildMemoryPs(PsWiring.Options.builder(settings.origin())
                    .insecureDev(false)
                    .signingKeyPath(null)
                    .trustFile(null)
                    .consentScopesFile(null)
                    .missionLifetimeSeconds(settings.missionLifetimeSeconds())
                    .selfJwksProvider(() -> Map.of("keys", List.of(Jwk.publicKeyToJwk(AS_KEY.getPublic(), "as-kid"))))
                    .build());
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    private static String agentToken(String sub, KeyPair key) {
        return AgentTokens.create(AgentTokens.Spec.builder(PS_ORIGIN, sub, jwk(key), AS_KEY.getPrivate(), "as-kid")
                .exp(Instant.now().getEpochSecond() + 3600)
                .build());
    }

    private MvcResult signedPost(String path, Map<String, Object> params, String sub, KeyPair key) throws Exception {
        byte[] body = Json.write(params).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = RequestSigner.sign(SignRequest.builder("POST", PS_ORIGIN + path)
                .headers(Map.of("Host", "localhost", "Content-Type", JSON_UTF8))
                .body(body)
                .keyPair(key)
                .scheme(new SignatureScheme.Jwt(agentToken(sub, key)))
                .additionalComponents(BODY_COMPONENTS)
                .build());
        MockHttpServletRequestBuilder request =
                post(path).contentType(JSON_UTF8).content(body);
        headers.forEach(request::header);
        return mvc.perform(request).andReturn();
    }

    private MvcResult agentPost(String path, Map<String, Object> params) throws Exception {
        return signedPost(path, params, AGENT_ID, AGENT_KEY);
    }

    private static Map<String, Object> json(MvcResult result) throws Exception {
        return Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private Map<String, Object> propose(Map<String, Object> proposal) throws Exception {
        MvcResult result = agentPost("/agent-missions", proposal);
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        return json(result);
    }

    private String proposeSimple() throws Exception {
        return (String) propose(Map.of(
                        "description",
                        "Book a table for two",
                        "tools",
                        List.of(Map.of("name", "book_table", "description", "Reserve a table"))))
                .get("s256");
    }

    @Test
    void metadataAdvertisesTheDraft11MissionEndpoint() throws Exception {
        mvc.perform(get("/.well-known/aauth-person.json"))
                .andExpect(jsonPath("$.mission_endpoint").value(PS_ORIGIN + "/agent-missions"));
    }

    @Test
    void approvalReturnsTheBlobBytesItsDigestAndNoApprover() throws Exception {
        Map<String, Object> approval = propose(Map.of("description", "Plan a trip"));
        byte[] blob = Base64.getUrlDecoder().decode((String) approval.get("mission"));

        assertThat(approval.get("s256")).isEqualTo(MissionUtils.s256HashBytes(blob));
        Map<String, Object> decoded = Json.readMap(new String(blob, StandardCharsets.UTF_8));
        assertThat(decoded)
                .containsEntry("agent", AGENT_ID)
                .containsEntry("description", "Plan a trip")
                .containsKeys("approved_at", "expires_at")
                .doesNotContainKeys("approver", "capabilities");
        assertThat(approval).containsKey("capabilities").doesNotContainKey("person_tokens");
    }

    @Test
    void proposedResourcesGetMissionBoundPersonTokens() throws Exception {
        Map<String, Object> approval =
                propose(Map.of("description", "Book flights", "resources", List.of("https://flights.example/")));
        String s256 = (String) approval.get("s256");

        @SuppressWarnings("unchecked")
        Map<String, String> tokens = (Map<String, String>) approval.get("person_tokens");
        assertThat(tokens).containsOnlyKeys("https://flights.example");
        Map<String, Object> claims =
                Jwts.parse(tokens.get("https://flights.example")).payload();
        assertThat(claims).containsEntry("mission_s256", s256).containsEntry("aud", "https://flights.example");

        Map<String, Object> blob = Json.readMap(
                new String(Base64.getUrlDecoder().decode((String) approval.get("mission")), StandardCharsets.UTF_8));
        assertThat(blob.get("approved_resources")).isEqualTo(List.of("https://flights.example"));
    }

    @Test
    void updateIsLoggedWithAVerifiableDigestAndLeavesTheMissionUnchanged() throws Exception {
        String s256 = proposeSimple();
        MvcResult result =
                agentPost("/agent-missions/" + s256, Map.of("action", "update", "description", "Hotel moved"));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String updateS256 = (String) json(result).get("s256");

        assertThat(ps.mission().getMission(s256)).isNotNull();
        var logged = ps.mission().getMissionLog(s256).stream()
                .filter(entry -> "mission_update".equals(entry.kind().value()))
                .findFirst()
                .orElseThrow();
        byte[] updateBytes =
                Base64.getUrlDecoder().decode((String) logged.payload().get("update"));
        assertThat(MissionUtils.s256HashBytes(updateBytes)).isEqualTo(updateS256);
    }

    @Test
    void acceptedCompletionTerminatesTheMissionWithReasonCompleted() throws Exception {
        String s256 = proposeSimple();
        MvcResult deferred =
                agentPost("/agent-missions/" + s256, Map.of("action", "completion", "summary", "Booked for 7pm"));
        assertThat(deferred.getResponse().getStatus()).isEqualTo(202);
        String pendingId = (String) json(deferred).get("pending_id");

        mvc.perform(post("/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"approved\":true}"))
                .andExpect(status().isOk());

        MvcResult after = agentPost("/agent-missions/" + s256, Map.of("action", "update", "description", "late"));
        assertThat(after.getResponse().getStatus()).isEqualTo(403);
        assertThat(json(after))
                .containsEntry("error", "mission_terminated")
                .containsEntry("termination_reason", "completed");
    }

    @Test
    void actionIsRequiredAndValidated() throws Exception {
        String s256 = proposeSimple();
        assertThat(agentPost("/agent-missions/" + s256, Map.of()).getResponse().getStatus())
                .isEqualTo(400);
        assertThat(agentPost("/agent-missions/" + s256, Map.of("action", "rename"))
                        .getResponse()
                        .getStatus())
                .isEqualTo(400);
        assertThat(agentPost("/agent-missions/not-a-hash", Map.of("action", "update"))
                        .getResponse()
                        .getStatus())
                .isEqualTo(400);
    }

    @Test
    void uppercaseAgentIdentifiersAreAcceptedAndComparedExactly() throws Exception {
        String upper = "aauth:Planner.7F3C@agent-server.example";
        MvcResult created = signedPost(
                "/agent-missions",
                Map.of(
                        "description",
                        "Book a table",
                        "tools",
                        List.of(Map.of("name", "search", "description", "Search venues"))),
                upper,
                AGENT_KEY);
        assertThat(created.getResponse().getStatus()).isEqualTo(200);
        String s256 = (String) json(created).get("s256");
        assertThat(ps.mission().getMission(s256).agentId()).isEqualTo(upper);

        Map<String, Object> update = Map.of("action", "update", "description", "x");
        assertThat(signedPost("/agent-missions/" + s256, update, upper.toLowerCase(java.util.Locale.ROOT), AGENT_KEY)
                        .getResponse()
                        .getStatus())
                .isEqualTo(404);
        assertThat(signedPost("/agent-missions/" + s256, update, upper, AGENT_KEY)
                        .getResponse()
                        .getStatus())
                .isEqualTo(200);
    }

    @Test
    void anotherAgentsMissionIsIndistinguishableFromAMissingOne() throws Exception {
        String s256 = proposeSimple();
        String missing = "A".repeat(43);
        MvcResult foreign = signedPost(
                "/agent-missions/" + s256, Map.of("action", "update", "description", "x"), OTHER_AGENT, OTHER_KEY);
        MvcResult absent = signedPost(
                "/agent-missions/" + missing, Map.of("action", "update", "description", "x"), OTHER_AGENT, OTHER_KEY);

        assertThat(foreign.getResponse().getStatus())
                .isEqualTo(404)
                .isEqualTo(absent.getResponse().getStatus());
        assertThat(foreign.getResponse().getContentAsString())
                .isEqualTo(absent.getResponse().getContentAsString());
        assertThat(json(foreign)).containsEntry("error", "mission_not_found");
    }

    @Test
    void permissionAcceptsMissionS256() throws Exception {
        String s256 = proposeSimple();
        MvcResult granted = agentPost("/permission", Map.of("action", "book_table", "mission_s256", s256));
        assertThat(granted.getResponse().getStatus()).isEqualTo(200);
        assertThat(json(granted)).containsEntry("permission", "granted");
    }

    @Test
    void draft11CompletionIsNotAnInteractionType() throws Exception {
        String s256 = proposeSimple();
        MvcResult result =
                agentPost("/interaction", Map.of("type", "completion", "summary", "done", "mission_s256", s256));
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
    }
}
