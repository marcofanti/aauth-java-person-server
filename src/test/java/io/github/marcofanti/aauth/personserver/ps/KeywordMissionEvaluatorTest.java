package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_mission_evaluator.py} — Layer 1 keyword evaluator. */
class KeywordMissionEvaluatorTest {

    private static Mission mission(String description, List<Map<String, String>> approvedTools) {
        return new Mission(
                "s",
                "{}".getBytes(StandardCharsets.UTF_8),
                MissionState.ACTIVE,
                "agent",
                Instant.parse("2026-05-15T00:00:00Z"),
                "user",
                "http://ps.test",
                description,
                approvedTools,
                null);
    }

    private static TokenRequestSummary req(String scope, String iss) {
        return new TokenRequestSummary("agent", iss, scope, null, false);
    }

    @Test
    void allowWhenScopeMatchesApprovedTool() {
        Mission m = mission(
                "Search the web for flight options.", List.of(Map.of("name", "search", "description", "Web search")));
        EvaluationDecision d = new KeywordMissionEvaluator().evaluate(m, List.of(), req("search", null));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.ALLOW);
        assertThat(d.reason()).contains("approved tool");
    }

    @Test
    void allowWhenOauthScopeActionMatchesTool() {
        Mission m = mission(
                "Read calendar to schedule a meeting.",
                List.of(Map.of("name", "read", "description", "Read calendar")));
        EvaluationDecision d = new KeywordMissionEvaluator().evaluate(m, List.of(), req("calendar:read", null));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.ALLOW);
    }

    @Test
    void allowWhenScopeMatchesDescriptionKeyword() {
        Mission m = mission("Plan a Tokyo trip — search flights and hotels.", List.of());
        EvaluationDecision d = new KeywordMissionEvaluator().evaluate(m, List.of(), req("search", null));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.ALLOW);
    }

    @Test
    void denyWhenMissionForbidsAction() {
        Mission m = mission("Plan a trip. Do not: delete any existing bookings.", null);
        EvaluationDecision d = new KeywordMissionEvaluator().evaluate(m, List.of(), req("delete", null));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.DENY);
    }

    @Test
    void denyWhenMissionForbidsHost() {
        Mission m = mission("Research only. Never:bank.example.", null);
        EvaluationDecision d =
                new KeywordMissionEvaluator().evaluate(m, List.of(), req("read", "https://bank.example"));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.DENY);
    }

    @Test
    void clarifyWhenHostKnownButScopeUnclear() {
        Mission m = mission("Plan a trip — use travel.example for itinerary lookups.", null);
        EvaluationDecision d =
                new KeywordMissionEvaluator().evaluate(m, List.of(), req("admin", "https://travel.example"));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.CLARIFY);
        assertThat(d.clarificationQuestion()).isNotNull().contains("travel.example");
    }

    @Test
    void escalateWhenNothingMatches() {
        Mission m = mission("Plan a Tokyo trip.", null);
        EvaluationDecision d =
                new KeywordMissionEvaluator().evaluate(m, List.of(), req("email:send", "https://email.example"));
        assertThat(d.decision()).isEqualTo(EvaluationDecision.Decision.ESCALATE);
    }
}
