package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.InvalidInteractionCodeException;
import io.github.marcofanti.aauth.personserver.ps.NotFoundException;
import io.github.marcofanti.aauth.personserver.ps.PendingGoneException;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.InteractionPendingSpec;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PermissionPendingSpec;
import io.github.marcofanti.aauth.personserver.ps.SlowDownException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Direct SqlPendingStore coverage: all pending kinds, updates, listings, and terminal paths. */
class SqlPendingStoreTest {

    @TempDir
    Path tempDir;

    private DbHolder db;
    private SqlPendingStore store;

    @BeforeEach
    void setUp() {
        db = DbHolder.fromUrl("sqlite:///" + tempDir.resolve("pending.db"));
        store = new SqlPendingStore(db.dataSource(), new SqlMissionState(db.dataSource()), "http://test.example", 600);
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    @Test
    void tokenPendingLifecycle() {
        String pendingId = store.createPending(TokenRequest.builder("agent", "rt")
                .secureMode(false)
                .justification("why")
                .build());
        store.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        DeferredResponse deferred = (DeferredResponse) store.getPending(pendingId, false);
        assertThat(deferred.requirement()).isEqualTo(RequirementLevel.INTERACTION);
        assertThat(deferred.code()).isEqualTo(store.getInteractionCode(pendingId));
        assertThat(deferred.interactionUrl()).isEqualTo("http://test.example/ui/consent.html");

        store.assertAgentOwnsPending(pendingId, "agent");
        assertThatThrownBy(() -> store.assertAgentOwnsPending(pendingId, "other"))
                .isInstanceOf(NotFoundException.class);

        PendingRecord viaCode = store.lookupCode(deferred.code());
        assertThat(viaCode.pendingId).isEqualTo(pendingId);

        store.setCallbackUrl(pendingId, "http://cb.example");
        store.replaceTokenRequest(pendingId, "new-rt", "new-just");
        PendingRecord record = store.getRecord(pendingId);
        assertThat(record.callbackUrl).isEqualTo("http://cb.example");
        assertThat(record.tokenRequest.resourceToken()).isEqualTo("new-rt");
        assertThat(record.tokenRequest.justification()).isEqualTo("new-just");

        List<Map<String, Object>> adminRows = store.listOpenPendingForAdmin();
        assertThat(adminRows).hasSize(1);
        assertThat(adminRows.getFirst()).containsEntry("agent_id", "agent");

        store.resolvePending(pendingId, new AuthTokenResponse("tok", 3600));
        assertThat(store.getPending(pendingId, false)).isInstanceOf(AuthTokenResponse.class);
        assertThatThrownBy(() -> store.getPending(pendingId, false)).isInstanceOf(NotFoundException.class);
        assertThatThrownBy(() -> store.lookupCode(deferred.code())).isInstanceOf(InvalidInteractionCodeException.class);
        assertThat(store.listOpenPendingForAdmin()).isEmpty();
    }

    @Test
    void interactionAndPermissionPendingsListForOwner() {
        String interactionId = store.createInteractionPending(new InteractionPendingSpec(
                "agent-i", "question", "owner-1", null, "summary", "Which?", null, null, "desc"));
        String permissionId = store.createPermissionPending(
                new PermissionPendingSpec("agent-p", "owner-1", null, "DeleteFile", "rm", Map.of("path", "/x")));
        store.updatePending(interactionId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        store.updatePending(permissionId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));

        List<PendingRecord> owned = store.listInteractionPendingForOwner("owner-1");
        assertThat(owned).hasSize(2);
        assertThat(store.listInteractionPendingForOwner("someone-else")).isEmpty();

        PendingRecord permission = store.getRecord(permissionId);
        assertThat(permission.permissionAction).isEqualTo("DeleteFile");
        assertThat(permission.permissionParameters).containsEntry("path", "/x");
    }

    @Test
    void missionPendingRoundTripsProposal() {
        String pendingId = store.createPending(new MissionProposal(
                "agent-m",
                "Do things.",
                List.of(new io.github.marcofanti.aauth.personserver.model.ToolSpec("t", "d")),
                "owner-2"));
        PendingRecord record = store.getRecord(pendingId);
        assertThat(record.missionProposal.agentId()).isEqualTo("agent-m");
        assertThat(record.missionProposal.tools()).hasSize(1);
        assertThat(record.ownerId).isEqualTo("owner-2");
    }

    @Test
    void deleteAndRateLimitAndStatusUpdates() {
        String pendingId = store.createPending(
                TokenRequest.builder("agent", "rt").secureMode(false).build());
        store.updatePending(
                pendingId,
                new PendingUpdate(
                        PendingStatus.INTERACTING, RequirementLevel.CLARIFICATION, "why?", 300, List.of("a")));
        DeferredResponse deferred = (DeferredResponse) store.getPending(pendingId, true);
        assertThat(deferred.status()).isEqualTo(PendingStatus.INTERACTING);
        assertThat(deferred.clarification()).isEqualTo("why?");
        assertThat(deferred.timeout()).isEqualTo(300);
        assertThat(deferred.options()).containsExactly("a");
        assertThatThrownBy(() -> store.getPending(pendingId, true)).isInstanceOf(SlowDownException.class);

        store.deletePending(pendingId);
        assertThatThrownBy(() -> store.getPending(pendingId, false)).isInstanceOf(PendingGoneException.class);
        assertThatThrownBy(() -> store.getRecord("missing")).isInstanceOf(NotFoundException.class);
    }
}
