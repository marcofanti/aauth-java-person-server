package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import org.junit.jupiter.api.Test;

/** TTL semantics: pending → expired, interacting → abandoned (mapped to denied). */
class PendingTtlTest {

    private static MemoryPendingStore storeWithTtl(int ttlSeconds) {
        return new MemoryPendingStore(new PsBackend(), "http://test.example", ttlSeconds);
    }

    private static String tokenPending(MemoryPendingStore store) {
        return store.createPending(
                TokenRequest.builder("agent", "fake-jwt").secureMode(false).build());
    }

    @Test
    void expiredPendingRaises408Expired() {
        MemoryPendingStore store = storeWithTtl(-1);
        String pendingId = tokenPending(store);
        assertThatThrownBy(() -> store.getPending(pendingId, false)).isInstanceOf(PendingExpiredException.class);
    }

    @Test
    void abandonedInteractingPendingRaisesDenied() {
        MemoryPendingStore store = storeWithTtl(-1);
        String pendingId = tokenPending(store);
        store.updatePending(pendingId, PendingUpdate.ofStatus(PendingStatus.INTERACTING));
        assertThatThrownBy(() -> store.getPending(pendingId, false))
                .isInstanceOf(PendingDeniedException.class)
                .extracting(e -> ((PendingDeniedException) e).reason())
                .isEqualTo("abandoned");
    }

    @Test
    void expiredCodeLookupIsInvalidAndPurged() {
        MemoryPendingStore store = storeWithTtl(-1);
        String pendingId = tokenPending(store);
        String code = store.getInteractionCode(pendingId);
        assertThatThrownBy(() -> store.lookupCode(code)).isInstanceOf(InvalidInteractionCodeException.class);
        assertThatThrownBy(() -> store.lookupCode(code)).isInstanceOf(InvalidInteractionCodeException.class);
    }

    @Test
    void freshPendingSurvivesTtlCheck() {
        MemoryPendingStore store = storeWithTtl(600);
        String pendingId = tokenPending(store);
        assertThat(store.getPending(pendingId, false)).isNotNull();
        assertThat(store.lookupCode(store.getInteractionCode(pendingId)).pendingId)
                .isEqualTo(pendingId);
    }

    @Test
    void replaceTokenRequestRejectsNonTokenPending() {
        MemoryPendingStore store = storeWithTtl(600);
        String pendingId =
                store.createPending(new io.github.marcofanti.aauth.personserver.model.MissionProposal("agent", "desc"));
        assertThatThrownBy(() -> store.replaceTokenRequest(pendingId, "new", null))
                .isInstanceOf(IllegalStateException.class);
    }
}
