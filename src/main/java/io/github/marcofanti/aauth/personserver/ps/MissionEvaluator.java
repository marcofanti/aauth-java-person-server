package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import java.util.List;

/**
 * Mission-aware decision making for the Person Server (Layer 1).
 *
 * <p>The protocol gives the PS <em>correlation</em> — every token request and tool call
 * references the approved mission by {@code s256}. It does not give <em>containment</em>:
 * whether a request is inside the approved authority. That judgement lives here.
 *
 * <p>The evaluator is consulted before the PS issues an auth token. Given the mission, the
 * full mission log, and a summary of the new request, it returns allow (issue, skip consent),
 * escalate (normal consent flow, reason shown to the user), clarify (return
 * {@code AAuth-Requirement: clarification} with a question), or deny (fail and log).
 */
public interface MissionEvaluator {

    EvaluationDecision evaluate(Mission mission, List<MissionLogEntry> log, TokenRequestSummary request);
}
