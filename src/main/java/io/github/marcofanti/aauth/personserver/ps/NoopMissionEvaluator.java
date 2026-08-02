package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import java.util.List;

/**
 * Default: always escalate to the standard consent flow. Use when no Layer 1 policy is
 * configured; behavior matches the pre-Layer-1 server.
 */
public class NoopMissionEvaluator implements MissionEvaluator {

    @Override
    public EvaluationDecision evaluate(Mission mission, List<MissionLogEntry> log, TokenRequestSummary request) {
        return EvaluationDecision.escalate("no evaluator configured");
    }
}
