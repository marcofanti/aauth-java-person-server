package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionOutcome;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;

/** Agent-facing {@code mission_endpoint} behavior (protocol §Mission Creation). */
public interface MissionLifecycle {

    /** Evaluate proposal; may defer (202) for review or clarification. */
    MissionOutcome createMission(MissionProposal proposal);

    /** Return mission by hash identifier. */
    Mission getMission(String s256);
}
