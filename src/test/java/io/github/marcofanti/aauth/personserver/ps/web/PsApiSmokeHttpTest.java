package io.github.marcofanti.aauth.personserver.ps.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.EvaluationDecision;
import io.github.marcofanti.aauth.personserver.ps.MemoryTokenBroker;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Port of {@code tests/test_ps_api_smoke.py} — insecure-dev Person Server HTTP flows. */
@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@AutoConfigureMockMvc
class PsApiSmokeHttpTest {

    private static final String ORIGIN = "http://testserver";

    @TestConfiguration
    static class Config {
        @Bean
        PsSettings psSettings() {
            return new PsSettings(
                    ORIGIN,
                    true,
                    "admintok",
                    "usertok",
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
                    "keyword");
        }

        @Bean
        PsContainer psContainer(PsSettings settings) {
            return PsWiring.buildMemoryPs(PsConfiguration.buildOptions(settings, null));
        }
    }

    @Autowired
    private MockMvc mvc;

    @Autowired
    private PsContainer ps;

    private static String s256FromMissionHeader(MvcResult result) {
        String header = result.getResponse().getHeader("AAuth-Mission");
        assertThat(header).isNotNull();
        Matcher matcher = Pattern.compile("s256=\"([^\"]+)\"").matcher(header);
        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private Map<String, Object> approveMission(String agent, String description) throws Exception {
        MvcResult result = mvc.perform(post("/mission")
                        .header("X-AAuth-Agent-Id", agent)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("description", description))))
                .andExpect(status().isOk())
                .andExpect(header().exists("AAuth-Mission"))
                .andReturn();
        Map<String, Object> blob = Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        return Map.of("approver", blob.get("approver"), "s256", s256FromMissionHeader(result));
    }

    @Test
    void wellKnownMetadataAndJwks() throws Exception {
        mvc.perform(get("/.well-known/aauth-person.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value(ORIGIN))
                .andExpect(jsonPath("$.token_endpoint").value(ORIGIN + "/token"))
                .andExpect(jsonPath("$.jwks_uri").value(ORIGIN + "/.well-known/jwks.json"));
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("OKP"));
    }

    @Test
    void missionRequiresAgentIdentityInInsecureDev() throws Exception {
        mvc.perform(post("/mission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("description", "x"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_signature"));
    }

    @Test
    void missionApprovalReturnsBlobBytesAndHeader() throws Exception {
        MvcResult result = mvc.perform(post("/mission")
                        .header("X-AAuth-Agent-Id", "smoke-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of(
                                "description",
                                "Plan a Tokyo trip.",
                                "tools",
                                java.util.List.of(Map.of("name", "search", "description", "Web search"))))))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> blob = Json.readMap(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertThat(blob).containsKeys("approver", "agent", "approved_at", "description", "approved_tools");
        assertThat(blob).containsEntry("approver", ORIGIN);
    }

    @Test
    void tokenDefersToConsentThenApprovalDeliversToken() throws Exception {
        Map<String, Object> ref = approveMission("flow-agent", "Plan a Tokyo trip.");
        MvcResult deferred = mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "flow-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("resource_token", "fake-jwt", "mission", ref))))
                .andExpect(status().isAccepted())
                .andExpect(header().exists("Location"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("pending"))
                .andExpect(jsonPath("$.requirement").value("interaction"))
                .andExpect(jsonPath("$.interaction_url").value(ORIGIN + "/ui/consent.html"))
                .andReturn();
        Map<String, Object> body = Json.readMap(deferred.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String code = (String) body.get("code");
        String pendingId = (String) body.get("pending_id");
        assertThat(deferred.getResponse().getHeader("AAuth-Requirement")).contains("requirement=interaction");

        mvc.perform(get("/consent").param("code", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pending_id").value(pendingId))
                .andExpect(jsonPath("$.pending_kind").value("token"))
                .andExpect(jsonPath("$.evaluator_reason").exists());

        mvc.perform(post("/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("approved", true))))
                .andExpect(status().isOk());

        mvc.perform(get("/pending/" + pendingId).header("X-AAuth-Agent-Id", "flow-agent"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.auth_token").exists())
                .andExpect(jsonPath("$.expires_in").value(3600));
    }

    @Test
    void deniedConsentYields403DeniedOnPoll() throws Exception {
        MvcResult deferred = mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "deny-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("resource_token", "fake-jwt"))))
                .andExpect(status().isAccepted())
                .andReturn();
        String pendingId = (String) Json.readMap(deferred.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("pending_id");
        mvc.perform(post("/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("approved", false))))
                .andExpect(status().isOk());
        mvc.perform(get("/pending/" + pendingId).header("X-AAuth-Agent-Id", "deny-agent"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("denied"));
    }

    @Test
    void cancelledPendingIsGoneAndUnknownIs404() throws Exception {
        MvcResult deferred = mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "cancel-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("resource_token", "fake-jwt"))))
                .andExpect(status().isAccepted())
                .andReturn();
        String pendingId = (String) Json.readMap(deferred.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("pending_id");
        mvc.perform(delete("/pending/" + pendingId).header("X-AAuth-Agent-Id", "cancel-agent"))
                .andExpect(status().isNoContent());
        mvc.perform(get("/pending/" + pendingId).header("X-AAuth-Agent-Id", "cancel-agent"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error").value("invalid_code"));
        mvc.perform(get("/pending/nope").header("X-AAuth-Agent-Id", "cancel-agent"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void permissionGrantedInsideApprovedToolsAndDeferredOutside() throws Exception {
        MvcResult missionResult = mvc.perform(post("/mission")
                        .header("X-AAuth-Agent-Id", "perm-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of(
                                "description",
                                "Search things.",
                                "tools",
                                java.util.List.of(Map.of("name", "WebSearch", "description", "search"))))))
                .andExpect(status().isOk())
                .andReturn();
        Map<String, Object> blob = Json.readMap(missionResult.getResponse().getContentAsString(StandardCharsets.UTF_8));
        Map<String, Object> ref =
                Map.of("approver", blob.get("approver"), "s256", s256FromMissionHeader(missionResult));

        mvc.perform(post("/permission")
                        .header("X-AAuth-Agent-Id", "perm-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("action", "WebSearch", "mission", ref))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permission").value("granted"));

        MvcResult deferred = mvc.perform(post("/permission")
                        .header("X-AAuth-Agent-Id", "perm-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("action", "DeleteFile", "description", "rm -rf", "mission", ref))))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.requirement").value("interaction"))
                .andReturn();
        Map<String, Object> body = Json.readMap(deferred.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String pendingId = (String) body.get("pending_id");
        String code = (String) body.get("code");

        mvc.perform(get("/consent").param("code", code))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pending_kind").value("permission"))
                .andExpect(jsonPath("$.permission_action").value("DeleteFile"));

        mvc.perform(post("/consent/" + pendingId + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("approved", false))))
                .andExpect(status().isOk());
        mvc.perform(get("/pending/" + pendingId).header("X-AAuth-Agent-Id", "perm-agent"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permission").value("denied"));
    }

    @Test
    void permissionWithoutMissionIsGranted() throws Exception {
        mvc.perform(post("/permission")
                        .header("X-AAuth-Agent-Id", "perm-agent-2")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("action", "Anything"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.permission").value("granted"));
    }

    @Test
    void auditReturns201AndAppearsInAdminMissionLog() throws Exception {
        Map<String, Object> ref = approveMission("audit-agent", "Search things.");
        mvc.perform(post("/audit")
                        .header("X-AAuth-Agent-Id", "audit-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(
                                Map.of("mission", ref, "action", "WebSearch", "result", Map.of("ok", true)))))
                .andExpect(status().isCreated());

        mvc.perform(get("/missions/" + ref.get("s256")).header("Authorization", "Bearer admintok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mission.s256").value(ref.get("s256")))
                .andExpect(jsonPath("$.log[?(@.kind == 'audit')]").exists());
    }

    @Test
    void terminatedMissionRejectsTokenAndPermission() throws Exception {
        Map<String, Object> ref = approveMission("term-agent", "Search things.");
        mvc.perform(patch("/missions/" + ref.get("s256"))
                        .header("Authorization", "Bearer admintok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("state", "terminated"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mission.state").value("terminated"));

        mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "term-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("resource_token", "fake-jwt", "mission", ref))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("mission_terminated"))
                .andExpect(jsonPath("$.mission_status").value("terminated"));
    }

    @Test
    void adminRoutesRequireBearerToken() throws Exception {
        mvc.perform(get("/missions")).andExpect(status().isUnauthorized());
        mvc.perform(get("/missions").header("Authorization", "Bearer wrong")).andExpect(status().isForbidden());
        mvc.perform(get("/missions").header("Authorization", "Bearer admintok")).andExpect(status().isOk());
        mvc.perform(get("/admin/pending").header("Authorization", "Bearer admintok"))
                .andExpect(status().isOk());
    }

    @Test
    void userRoutesRequireUserToken() throws Exception {
        mvc.perform(get("/user/missions")).andExpect(status().isUnauthorized());
        mvc.perform(get("/user/missions").header("Authorization", "Bearer usertok"))
                .andExpect(status().isOk());
        mvc.perform(get("/user/consent").header("Authorization", "Bearer usertok"))
                .andExpect(status().isOk());
    }

    @Test
    void consentScopesAdminCrud() throws Exception {
        mvc.perform(get("/admin/consent-scopes").header("Authorization", "Bearer admintok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopes[0]").value("require:user"));
        mvc.perform(post("/admin/consent-scopes")
                        .header("Authorization", "Bearer admintok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("scope", "require:approval"))))
                .andExpect(status().isCreated());
        mvc.perform(post("/admin/consent-scopes")
                        .header("Authorization", "Bearer admintok")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("scope", "require:approval"))))
                .andExpect(status().isConflict());
        mvc.perform(delete("/admin/consent-scopes/require:approval").header("Authorization", "Bearer admintok"))
                .andExpect(status().isNoContent());
    }

    @Test
    void trustedAgentServersListIncludesImplicitSelf() throws Exception {
        mvc.perform(get("/person/trusted-agent-servers").header("Authorization", "Bearer admintok"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].issuer").value(ORIGIN))
                .andExpect(jsonPath("$[0].implicit").value(true));
        mvc.perform(delete("/person/trusted-agent-servers")
                        .param("issuer", "http://nope.example")
                        .header("Authorization", "Bearer admintok"))
                .andExpect(status().isNotFound());
    }

    @Test
    void legacyInteractionAliasesWork() throws Exception {
        MvcResult deferred = mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "legacy-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("resource_token", "fake-jwt"))))
                .andExpect(status().isAccepted())
                .andReturn();
        Map<String, Object> body = Json.readMap(deferred.getResponse().getContentAsString(StandardCharsets.UTF_8));
        mvc.perform(get("/interaction").param("code", (String) body.get("code")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.pending_id").value(body.get("pending_id")));
        mvc.perform(post("/interaction/" + body.get("pending_id") + "/decision")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(Json.write(Map.of("approved", true))))
                .andExpect(status().isOk());
    }

    @Test
    void evaluatorAllowIssuesImmediatelyOverHttp() throws Exception {
        Map<String, Object> ref = approveMission("allow-agent", "Search the web.");
        ((MemoryTokenBroker) ps.tokenBroker())
                .setEvaluator((m, log, request) -> EvaluationDecision.allow("scope inside mission"));
        try {
            mvc.perform(post("/token")
                            .header("X-AAuth-Agent-Id", "allow-agent")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(Json.write(Map.of("resource_token", "fake-jwt", "mission", ref))))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.auth_token").exists());
        } finally {
            ((MemoryTokenBroker) ps.tokenBroker())
                    .setEvaluator(new io.github.marcofanti.aauth.personserver.ps.KeywordMissionEvaluator());
        }
    }

    @Test
    void invalidBodyOnAgentPathIsAAuth400() throws Exception {
        mvc.perform(post("/token")
                        .header("X-AAuth-Agent-Id", "bad-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void unknownConsentCodeIs410InvalidCode() throws Exception {
        mvc.perform(get("/consent").param("code", "nope"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error").value("invalid_code"));
    }
}
