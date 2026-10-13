package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class Draft11MissionStatusTest {

    private static Mission mission(Map<String, Object> blob) {
        byte[] bytes = Json.write(blob).getBytes(StandardCharsets.UTF_8);
        return new Mission(
                MissionUtils.s256HashBytes(bytes),
                bytes,
                MissionState.ACTIVE,
                "agent",
                Instant.now(),
                "user",
                "http://ps.example",
                "d",
                null,
                null);
    }

    private static Map<String, Object> draft11Blob(Instant expiresAt) {
        Map<String, Object> blob = new LinkedHashMap<>();
        blob.put("agent", "agent");
        blob.put("approved_at", "2026-10-01T00:00:00Z");
        blob.put("description", "d");
        if (expiresAt != null) {
            blob.put("expires_at", expiresAt.toString());
        }
        return blob;
    }

    @Test
    void anExpiredMissionTerminatesForGoodWithReasonExpired() {
        PsBackend backend = new PsBackend();
        Mission expired = mission(draft11Blob(Instant.now().minusSeconds(5)));
        backend.setMission(expired);
        Draft11MissionStatus status = new Draft11MissionStatus(backend);

        assertThatThrownBy(() -> status.requireActive(expired))
                .isInstanceOfSatisfying(
                        MissionTerminatedException.class,
                        e -> assertThat(e.reason()).isEqualTo("expired"));
        Mission stored = backend.getMission(expired.s256());
        assertThat(stored.state()).isEqualTo(MissionState.TERMINATED);

        // Terminated is final and keeps its reason on every later check.
        assertThatThrownBy(() -> status.requireActive(stored))
                .isInstanceOfSatisfying(
                        MissionTerminatedException.class,
                        e -> assertThat(e.reason()).isEqualTo("expired"));
        status.terminate(stored, "revoked");
        assertThat(status.terminationReason(expired.s256())).isEqualTo("expired");
    }

    @Test
    void anUnexpiredMissionStaysActiveAndCapsTokens() {
        Instant expires = Instant.now().plusSeconds(600);
        Mission live = mission(draft11Blob(expires));
        PsBackend backend = new PsBackend();
        backend.setMission(live);

        assertThat(new Draft11MissionStatus(backend).requireActive(live).state())
                .isEqualTo(MissionState.ACTIVE);
        assertThat(Draft11MissionStatus.capFor(live)).isEqualTo(expires.getEpochSecond());
        assertThat(Draft11MissionStatus.capFor(mission(draft11Blob(null)))).isNull();
    }

    @Test
    void draft10MissionsAreNeverTreatedAsDraft11() {
        Map<String, Object> blob = draft11Blob(Instant.now().minusSeconds(5));
        blob.put("approver", "http://ps.example");
        Mission draft10 = mission(blob);
        PsBackend backend = new PsBackend();
        backend.setMission(draft10);

        assertThat(Draft11MissionStatus.isDraft11(draft10)).isFalse();
        assertThat(new Draft11MissionStatus(backend).requireActive(draft10).state())
                .isEqualTo(MissionState.ACTIVE);
        assertThat(Draft11MissionStatus.capFor(draft10)).isNull();
    }
}
