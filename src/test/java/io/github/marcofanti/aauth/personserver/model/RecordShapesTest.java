package io.github.marcofanti.aauth.personserver.model;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.ps.IssuedTokenStore;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RecordShapesTest {

    @Test
    void plainRecordsConstruct() {
        assertThat(new ToolSpec("WebSearch", "search").name()).isEqualTo("WebSearch");
        assertThat(new MissionLogEntry(Instant.EPOCH, MissionLogKind.AUDIT, Map.of()).kind())
                .isEqualTo(MissionLogKind.AUDIT);
        assertThat(new DecisionResult(null).redirectUrl()).isNull();
        assertThat(new InteractionTerminalResult(Map.of("status", "done")).body())
                .containsEntry("status", "done");
        assertThat(new PermissionRequest("a", "d", Map.of(), null, "agent").action())
                .isEqualTo("a");
        assertThat(new AuditRequest(new MissionRef("p", "s"), "a", null, null, null, "agent")
                        .mission()
                        .s256())
                .isEqualTo("s");
        assertThat(new AgentInteractionRequest("completion", null, null, null, null, "done", null, "agent").type())
                .isEqualTo("completion");
    }

    @Test
    void metadataRecordsConstruct() {
        assertThat(new PSMetadata("i", "t", "m", null, null, null, null, "j").issuer())
                .isEqualTo("i");
        assertThat(new ASMetadata("i", "t", "j").tokenEndpoint()).isEqualTo("t");
        assertThat(new AgentServerMetadata("i", "j", "n", "r", "f").clientName())
                .isEqualTo("n");
    }

    @Test
    void storeHelperRecordsConstruct() {
        PendingRequestStore.PendingUpdate update =
                PendingRequestStore.PendingUpdate.ofStatus(PendingStatus.INTERACTING);
        assertThat(update.status()).isEqualTo(PendingStatus.INTERACTING);
        assertThat(update.requirement()).isNull();

        IssuedTokenStore.IssuedToken issued = new IssuedTokenStore.IssuedToken(
                "tok", "agent", "user", "https://gateway.uma.lab", "read", "why", "auto", Instant.EPOCH);
        assertThat(issued.issueMethod()).isEqualTo("auto");
    }
}
