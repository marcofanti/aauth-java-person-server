package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class EvaluationDecisionTest {

    @Test
    void factoriesMatchPythonSemantics() {
        assertThat(EvaluationDecision.allow("in scope").decision()).isEqualTo(EvaluationDecision.Decision.ALLOW);
        assertThat(EvaluationDecision.escalate("boundary").reason()).isEqualTo("boundary");
        assertThat(EvaluationDecision.deny("out of scope").decision()).isEqualTo(EvaluationDecision.Decision.DENY);
    }

    @Test
    void clarifyDefaultsReasonToQuestion() {
        EvaluationDecision decision = EvaluationDecision.clarify("which account?");
        assertThat(decision.decision()).isEqualTo(EvaluationDecision.Decision.CLARIFY);
        assertThat(decision.reason()).isEqualTo("which account?");
        assertThat(decision.clarificationQuestion()).isEqualTo("which account?");

        EvaluationDecision withReason = EvaluationDecision.clarify("which account?", "ambiguous");
        assertThat(withReason.reason()).isEqualTo("ambiguous");
        assertThat(withReason.clarificationQuestion()).isEqualTo("which account?");
    }

    @Test
    void decisionWireValues() {
        assertThat(EvaluationDecision.Decision.ALLOW.value()).isEqualTo("allow");
        assertThat(EvaluationDecision.Decision.ESCALATE.value()).isEqualTo("escalate");
        assertThat(EvaluationDecision.Decision.CLARIFY.value()).isEqualTo("clarify");
        assertThat(EvaluationDecision.Decision.DENY.value()).isEqualTo("deny");
    }

    @Test
    void noopEvaluatorAlwaysEscalates() {
        Mission mission = new Mission(
                "s",
                new byte[0],
                MissionState.ACTIVE,
                "agent",
                Instant.EPOCH,
                null,
                "https://ps.uma.lab",
                "d",
                null,
                null);
        EvaluationDecision decision = new NoopMissionEvaluator()
                .evaluate(mission, List.of(), new TokenRequestSummary("agent", null, null, null, false));
        assertThat(decision.decision()).isEqualTo(EvaluationDecision.Decision.ESCALATE);
    }
}
