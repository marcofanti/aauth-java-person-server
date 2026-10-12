package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.MemoryRevocationStore;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import io.github.marcofanti.aauth.personserver.ps.RevocationStore;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Revocation state keyed by (iss, jti) behaves the same in memory and in SQL (§11.12.1). */
class SqlRevocationStoreTest {

    @TempDir
    Path tempDir;

    private DbHolder db;

    @BeforeEach
    void setUp() {
        db = DbHolder.fromUrl("sqlite:///" + tempDir.resolve("revocation.db"));
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    private void forBoth(Consumer<RevocationStore> check) {
        check.accept(new MemoryRevocationStore());
        check.accept(new SqlRevocationStore(db.dataSource()));
    }

    @Test
    void revocationsAreKeyedByIssuerAndJti() {
        forBoth(store -> {
            store.revoke("https://ap.example/", "t-1", 100);
            store.revoke("https://ap.example", "t-1", 100);

            assertThat(store.isRevoked("https://ap.example", "t-1")).isTrue();
            assertThat(store.isRevoked("https://ap.example/", "t-1")).isTrue();
            assertThat(store.isRevoked("https://other.example", "t-1")).isFalse();
            assertThat(store.isRevoked("https://ap.example", "t-2")).isFalse();
            assertThat(store.isRevoked(null, "t-1")).isFalse();
            assertThat(store.isRevoked("https://ap.example", null)).isFalse();
        });
    }

    @Test
    void agentTokenRecordsKeepTheFirstSub() {
        forBoth(store -> {
            store.recordAgentToken("https://ap.example", "a-1", "aauth:planner@ap.example", 100);
            store.recordAgentToken("https://ap.example/", "a-1", "aauth:other@ap.example", 100);

            assertThat(store.agentSub("https://ap.example", "a-1")).isEqualTo("aauth:planner@ap.example");
            assertThat(store.agentSub("https://ap.example", "a-2")).isNull();
        });
    }

    @Test
    void sqlPendingKeepsFieldsSetOnTheRecordAndFindsItsResourceToken() {
        SqlPendingStore store =
                new SqlPendingStore(db.dataSource(), new SqlMissionState(db.dataSource()), "https://ps.example", 600);
        String pendingId =
                store.createPending(TokenRequest.builder("agent", "rt").build());
        PendingRecord record = store.getRecord(pendingId);
        record.verifiedResourceClaims = Map.of("iss", "https://rs.example", "jti", "rt-1");
        store.saveRecord(record);

        assertThat(store.getRecord(pendingId).verifiedResourceClaims).containsEntry("jti", "rt-1");
        assertThat(store.openPendingForResourceToken("https://rs.example/", "rt-1"))
                .isEqualTo(List.of(pendingId));
        assertThat(store.openPendingForResourceToken("https://rs.example", "rt-2"))
                .isEmpty();

        store.failPending(pendingId, "revoked");
        assertThat(store.openPendingForResourceToken("https://rs.example", "rt-1"))
                .isEmpty();
    }

    @Test
    void agentRevocationTimesKeepTheLatest() {
        forBoth(store -> {
            assertThat(store.agentRevokedAt("aauth:a@ap")).isNull();
            store.recordAgentRevocation("aauth:a@ap", 200);
            store.recordAgentRevocation("aauth:a@ap", 100);
            assertThat(store.agentRevokedAt("aauth:a@ap")).isEqualTo(200L);
            store.recordAgentRevocation("aauth:a@ap", 300);
            assertThat(store.agentRevokedAt("aauth:a@ap")).isEqualTo(300L);
        });
    }

    @Test
    void aPendingPastItsDeadlineEndsExpiredEvenWhileInteracting() {
        SqlPendingStore store =
                new SqlPendingStore(db.dataSource(), new SqlMissionState(db.dataSource()), "https://ps.example", 600);
        String pendingId =
                store.createPending(TokenRequest.builder("agent", "rt").build());
        store.updatePending(
                pendingId,
                io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate.ofStatus(
                        io.github.marcofanti.aauth.personserver.model.PendingStatus.INTERACTING));
        PendingRecord record = store.getRecord(pendingId);
        record.deadline = java.time.Instant.now().getEpochSecond() - 1;
        store.saveRecord(record);

        assertThat(org.assertj.core.api.Assertions.catchThrowable(() -> store.getPending(pendingId, false)))
                .isInstanceOf(io.github.marcofanti.aauth.personserver.ps.PendingExpiredException.class);
    }
}
