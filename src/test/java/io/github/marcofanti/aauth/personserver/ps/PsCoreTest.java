package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.model.AgentInteractionRequest;
import io.github.marcofanti.aauth.personserver.model.AuditRequest;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DecisionResult;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.InteractionTerminalResult;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionOutcome;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PermissionRequest;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Core PS behavior through the in-memory container (mirrors the Python impl semantics). */
class PsCoreTest {

    private static PsContainer container(String evaluator) {
        return PsWiring.buildMemoryPs(PsWiring.Options.builder("http://test.example")
                .signingKeyPath(null)
                .trustFile(null)
                .consentScopesFile(null)
                .insecureDev(true)
                .missionEvaluator(evaluator)
                .build());
    }

    private static Mission approveMission(PsContainer ps, String agent, String description, List<ToolSpec> tools) {
        MissionOutcome outcome = ps.lifecycle().createMission(new MissionProposal(agent, description, tools, "user"));
        assertThat(outcome).isInstanceOf(Mission.class);
        return (Mission) outcome;
    }

    private static TokenRequest insecureTokenRequest(String agent, MissionRef ref) {
        return TokenRequest.builder(agent, "fake-jwt")
                .mission(ref)
                .secureMode(false)
                .build();
    }

    @Test
    void missionAutoApproveRecordsLogAndBlob() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a1", "Plan a Tokyo trip.", List.of(new ToolSpec("search", "Web search")));
        assertThat(mission.state()).isEqualTo(MissionState.ACTIVE);
        assertThat(mission.approver()).isEqualTo("http://test.example");
        Map<String, Object> blob = MissionUtils.missionBlobDict(mission);
        assertThat(blob).containsKeys("approver", "agent", "approved_at", "description", "approved_tools");
        assertThat(mission.s256()).isEqualTo(MissionUtils.s256HashBytes(mission.blobBytes()));
        List<MissionLogEntry> log = ps.mission().getMissionLog(mission.s256());
        assertThat(log).hasSize(1);
        assertThat(log.getFirst().kind()).isEqualTo(MissionLogKind.MISSION_APPROVED);
    }

    @Test
    void insecureTokenRequestDefersToConsentAndApproveDeliversFakeToken() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a1", "Plan a trip.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());

        TokenOutcome outcome = ps.tokenBroker().requestToken(insecureTokenRequest("a1", ref));
        assertThat(outcome).isInstanceOf(DeferredResponse.class);
        DeferredResponse deferred = (DeferredResponse) outcome;
        assertThat(deferred.requirement()).isEqualTo(RequirementLevel.INTERACTION);
        assertThat(deferred.interactionUrl()).isEqualTo("http://test.example/ui/consent.html");
        assertThat(deferred.code()).isNotNull();

        ConsentContext context = ps.userConsent().getConsentContext(deferred.code());
        assertThat(context.pendingKind()).isEqualTo("token");
        assertThat(context.mission().s256()).isEqualTo(mission.s256());

        DecisionResult result = ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
        assertThat(result.redirectUrl()).isNull();

        PendingPollOutcome polled = ps.tokenBroker().getPending(deferred.pendingId(), "a1");
        assertThat(polled).isInstanceOf(AuthTokenResponse.class);
        assertThat(((AuthTokenResponse) polled).authToken()).startsWith("aa-auth.fake.");
    }

    @Test
    void deniedConsentFailsPendingWith403Denied() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a2", "Plan a trip.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker().requestToken(insecureTokenRequest("a2", ref));
        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(false));
        assertThatThrownBy(() -> ps.tokenBroker().getPending(deferred.pendingId(), "a2"))
                .isInstanceOf(PendingDeniedException.class);
    }

    @Test
    void pendingIsScopedToOwningAgent() {
        PsContainer ps = container(null);
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker()
                .requestToken(
                        TokenRequest.builder("a3", "fake-jwt").secureMode(false).build());
        assertThatThrownBy(() -> ps.tokenBroker().getPending(deferred.pendingId(), "other-agent"))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void cancelledPendingIsGone() {
        PsContainer ps = container(null);
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker()
                .requestToken(
                        TokenRequest.builder("a4", "fake-jwt").secureMode(false).build());
        ps.tokenBroker().cancelRequest(deferred.pendingId(), "a4");
        assertThatThrownBy(() -> ps.tokenBroker().getPending(deferred.pendingId(), "a4"))
                .isInstanceOf(PendingGoneException.class);
    }

    @Test
    void terminalTokenIsDeliveredExactlyOnce() {
        PsContainer ps = container(null);
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker()
                .requestToken(
                        TokenRequest.builder("a5", "fake-jwt").secureMode(false).build());
        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
        PendingPollOutcome first = ps.tokenBroker().getPending(deferred.pendingId(), "a5");
        assertThat(first).isInstanceOf(AuthTokenResponse.class);
        assertThatThrownBy(() -> ps.tokenBroker().getPending(deferred.pendingId(), "a5"))
                .isInstanceOf(NotFoundException.class);
    }

    @Test
    void rapidPollingTriggersSlowDown() {
        PsContainer ps = container(null);
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker()
                .requestToken(
                        TokenRequest.builder("a6", "fake-jwt").secureMode(false).build());
        ps.tokenBroker().getPending(deferred.pendingId(), "a6");
        assertThatThrownBy(() -> ps.tokenBroker().getPending(deferred.pendingId(), "a6"))
                .isInstanceOf(SlowDownException.class);
    }

    @Test
    void permissionWithoutMissionIsGrantedSpecPermissive() {
        PsContainer ps = container(null);
        PsGovernance.PermissionResponse response =
                ps.governance().postPermission(new PermissionRequest("WebSearch", null, null, null, "a7"));
        assertThat(response).isInstanceOf(PsGovernance.PermissionResponse.Granted.class);
    }

    @Test
    void permissionInsideApprovedToolsGrantsAndLogs() {
        PsContainer ps = container(null);
        Mission mission =
                approveMission(ps, "a8", "Search things.", List.of(new ToolSpec("WebSearch", "search the web")));
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        PsGovernance.PermissionResponse response =
                ps.governance().postPermission(new PermissionRequest("WebSearch", "look", Map.of("q", "x"), ref, "a8"));
        assertThat(response).isInstanceOf(PsGovernance.PermissionResponse.Granted.class);
        List<MissionLogEntry> log = ps.mission().getMissionLog(mission.s256());
        MissionLogEntry last = log.getLast();
        assertThat(last.kind()).isEqualTo(MissionLogKind.PERMISSION);
        assertThat(last.payload()).containsEntry("decided_by", "approved_tools");
    }

    @Test
    void permissionOutsideApprovedToolsDefersAndUserDecides() {
        PsContainer ps = container(null);
        Mission mission =
                approveMission(ps, "a9", "Search things.", List.of(new ToolSpec("WebSearch", "search the web")));
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        PsGovernance.PermissionResponse response = ps.governance()
                .postPermission(new PermissionRequest("DeleteFile", "rm", Map.of("path", "/x"), ref, "a9"));
        assertThat(response).isInstanceOf(PsGovernance.PermissionResponse.Deferred.class);
        DeferredResponse deferred = ((PsGovernance.PermissionResponse.Deferred) response).deferred();

        ConsentContext context = ps.userConsent().getConsentContext(deferred.code());
        assertThat(context.pendingKind()).isEqualTo("permission");
        assertThat(context.permissionAction()).isEqualTo("DeleteFile");

        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
        PendingPollOutcome polled = ps.tokenBroker().getPending(deferred.pendingId(), "a9");
        assertThat(polled).isInstanceOf(InteractionTerminalResult.class);
        assertThat(((InteractionTerminalResult) polled).body()).containsEntry("permission", "granted");

        MissionLogEntry last = ps.mission().getMissionLog(mission.s256()).getLast();
        assertThat(last.payload()).containsEntry("decided_by", "user").containsEntry("result", "granted");
    }

    @Test
    void permissionAgainstTerminatedMissionIsRejected() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a10", "Search things.", List.of());
        ps.missionControl().terminateMission(mission.s256());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        assertThatThrownBy(() -> ps.governance().postPermission(new PermissionRequest("X", null, null, ref, "a10")))
                .isInstanceOf(MissionTerminatedException.class);
    }

    @Test
    void auditAppendsToMissionLog() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a11", "Search things.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        ps.governance().postAudit(new AuditRequest(ref, "WebSearch", "done", Map.of(), Map.of("ok", true), "a11"));
        MissionLogEntry last = ps.mission().getMissionLog(mission.s256()).getLast();
        assertThat(last.kind()).isEqualTo(MissionLogKind.AUDIT);
        assertThat(last.payload()).containsEntry("action", "WebSearch");
    }

    @Test
    void completionInteractionTerminatesMissionOnApproval() {
        PsContainer ps = container(null);
        Mission mission = approveMission(ps, "a12", "Search things.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        DeferredResponse deferred = ps.governance()
                .postAgentInteraction(new AgentInteractionRequest(
                        "completion", "all done", null, null, null, "trip planned", ref, "a12"));
        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
        assertThat(ps.mission().getMission(mission.s256()).state()).isEqualTo(MissionState.TERMINATED);
        PendingPollOutcome polled = ps.tokenBroker().getPending(deferred.pendingId(), "a12");
        assertThat(((InteractionTerminalResult) polled).body()).containsEntry("status", "ok");
    }

    @Test
    void questionInteractionDeliversAnswer() {
        PsContainer ps = container(null);
        DeferredResponse deferred = ps.governance()
                .postAgentInteraction(
                        new AgentInteractionRequest("question", null, null, null, "Which city?", null, null, "a13"));
        ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true, null, "Tokyo"));
        PendingPollOutcome polled = ps.tokenBroker().getPending(deferred.pendingId(), "a13");
        assertThat(((InteractionTerminalResult) polled).body()).containsEntry("answer", "Tokyo");
    }

    @Test
    void completionWithoutMissionIsRejected() {
        PsContainer ps = container(null);
        assertThatThrownBy(() -> ps.governance()
                        .postAgentInteraction(
                                new AgentInteractionRequest("completion", null, null, null, null, "done", null, "a14")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void evaluatorAllowIssuesImmediately() {
        PsContainer ps = container("keyword");
        Mission mission = approveMission(ps, "a15", "Search the web.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        ((MemoryTokenBroker) ps.tokenBroker())
                .setEvaluator((m, log, request) -> EvaluationDecision.allow("scope inside mission"));
        TokenOutcome outcome = ps.tokenBroker().requestToken(insecureTokenRequest("a15", ref));
        assertThat(outcome).isInstanceOf(AuthTokenResponse.class);
        List<MissionLogEntry> log = ps.mission().getMissionLog(mission.s256());
        assertThat(log.stream()
                        .filter(e -> e.kind() == MissionLogKind.TOKEN_REQUEST)
                        .map(e -> e.payload().get("decision")))
                .contains("allow");
    }

    @Test
    void evaluatorDenyThrowsMissionDenied() {
        PsContainer ps = container("keyword");
        Mission mission = approveMission(ps, "a16", "Research mode.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        ((MemoryTokenBroker) ps.tokenBroker())
                .setEvaluator((m, log, request) -> EvaluationDecision.deny("test forced deny"));
        assertThatThrownBy(() -> ps.tokenBroker().requestToken(insecureTokenRequest("a16", ref)))
                .isInstanceOf(MissionDeniedException.class)
                .hasMessageContaining("test forced deny");
    }

    @Test
    void evaluatorClarifyReturnsClarificationDeferred() {
        PsContainer ps = container("keyword");
        Mission mission = approveMission(ps, "a17", "Plan a trip via travel.example.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        ((MemoryTokenBroker) ps.tokenBroker())
                .setEvaluator((m, log, request) ->
                        EvaluationDecision.clarify("Which itinerary are you fetching?", "ambiguous request"));
        TokenOutcome outcome = ps.tokenBroker().requestToken(insecureTokenRequest("a17", ref));
        DeferredResponse deferred = (DeferredResponse) outcome;
        assertThat(deferred.requirement()).isEqualTo(RequirementLevel.CLARIFICATION);
        assertThat(deferred.clarification()).isEqualTo("Which itinerary are you fetching?");

        DeferredResponse after =
                ps.tokenBroker().postClarificationResponse(deferred.pendingId(), "a17", "the Kyoto one");
        assertThat(after.requirement()).isEqualTo(RequirementLevel.INTERACTION);
        assertThat(after.status()).isEqualTo(PendingStatus.PENDING);
    }

    @Test
    void evaluatorEscalationReasonVisibleInConsentContext() {
        PsContainer ps = container("keyword");
        Mission mission = approveMission(ps, "a18", "Plan a Tokyo trip.", List.of());
        MissionRef ref = new MissionRef(mission.approver(), mission.s256());
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker().requestToken(insecureTokenRequest("a18", ref));
        ConsentContext context = ps.userConsent().getConsentContext(deferred.code());
        assertThat(context.evaluatorReason()).contains("no overlap");
    }

    @Test
    void tokenWithoutMissionSkipsEvaluator() {
        PsContainer ps = container("keyword");
        TokenOutcome outcome = ps.tokenBroker()
                .requestToken(TokenRequest.builder("a19", "fake-jwt")
                        .secureMode(false)
                        .build());
        DeferredResponse deferred = (DeferredResponse) outcome;
        assertThat(deferred.requirement()).isEqualTo(RequirementLevel.INTERACTION);
    }

    @Test
    void missionControlListsAndTerminates() {
        PsContainer ps = container(null);
        Mission first = approveMission(ps, "agent-a", "First mission.", List.of());
        approveMission(ps, "agent-b", "Second mission.", List.of());
        assertThat(ps.missionControl().listMissions(null, null)).hasSize(2);
        assertThat(ps.missionControl().listMissions("agent-a", null)).hasSize(1);
        assertThat(ps.missionControl().listMissionsForOwner("user")).hasSize(2);
        Mission terminated = ps.missionControl().terminateMission(first.s256());
        assertThat(terminated.state()).isEqualTo(MissionState.TERMINATED);
        assertThat(ps.missionControl().listMissions(null, MissionState.ACTIVE)).hasSize(1);
        assertThatThrownBy(() -> ps.missionControl().terminateMission(first.s256()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> ps.missionControl().inspectMission("nope")).isInstanceOf(NotFoundException.class);
    }

    @Test
    void adminPendingListShowsOpenRows() {
        PsContainer ps = container(null);
        DeferredResponse deferred = (DeferredResponse) ps.tokenBroker()
                .requestToken(TokenRequest.builder("a20", "fake-jwt")
                        .secureMode(false)
                        .justification("please")
                        .build());
        List<Map<String, Object>> rows = ps.pendingStore().listOpenPendingForAdmin();
        assertThat(rows).hasSize(1);
        Map<String, Object> row = rows.getFirst();
        assertThat(row).containsEntry("pending_id", deferred.pendingId());
        assertThat(row).containsEntry("kind", "token");
        assertThat(row).containsEntry("agent_id", "a20");
        assertThat(row).containsEntry("justification", "please");
    }

    @Test
    void unknownEvaluatorNameIsRejected() {
        assertThatThrownBy(() -> container("llm")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void invalidConsentCodeIsRejected() {
        PsContainer ps = container(null);
        assertThatThrownBy(() -> ps.userConsent().getConsentContext("nope"))
                .isInstanceOf(InvalidInteractionCodeException.class);
    }
}
