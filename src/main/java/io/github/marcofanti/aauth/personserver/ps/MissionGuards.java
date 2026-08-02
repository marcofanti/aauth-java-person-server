package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionRef;
import io.github.marcofanti.aauth.personserver.model.MissionState;

/** Validate MissionRef against backend state. */
public final class MissionGuards {

    private MissionGuards() {}

    public static Mission requireActiveMission(MissionStatePort mission, MissionRef ref) {
        Mission found = mission.getMission(ref.s256());
        if (found == null) {
            throw new NotFoundException();
        }
        if (!MissionUtils.stripTrailingSlash(found.approver())
                .equals(MissionUtils.stripTrailingSlash(ref.approver()))) {
            throw new NotFoundException();
        }
        if (found.state() != MissionState.ACTIVE) {
            throw new MissionTerminatedException();
        }
        return found;
    }
}
