package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** SQL person-token ledger and person_token pendings survive in the shared schema. */
class SqlPersonTokenLedgerTest {

    private static final long NOW = Instant.now().getEpochSecond();

    @TempDir
    Path tempDir;

    private DbHolder db;

    @BeforeEach
    void setUp() {
        db = DbHolder.fromUrl("sqlite:///" + tempDir.resolve("ledger.db"));
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    @Test
    void approvalsAndIssuanceRecordsPersist() {
        SqlPersonTokenLedger ledger = new SqlPersonTokenLedger(db.dataSource());
        ledger.approve("user", "https://a.example/");
        ledger.approve("user", "https://a.example");
        ledger.recordIssued(new PersonTokenLedger.Issued("j1", "agent", "user", "https://a.example", "s", NOW + 600));
        ledger.recordIssued(new PersonTokenLedger.Issued("j2", "agent", "user", "https://b.example", "s", NOW - 1));

        SqlPersonTokenLedger reopened = new SqlPersonTokenLedger(db.dataSource());
        assertThat(reopened.isApproved("user", "https://a.example")).isTrue();
        assertThat(reopened.isApproved("user", "https://b.example")).isFalse();
        assertThat(reopened.findByJti("j1").aud()).isEqualTo("https://a.example");
        assertThat(reopened.findByJti("missing")).isNull();
        assertThat(reopened.distinctLiveResources("agent", "https://z.example", NOW))
                .isEqualTo(1);
        assertThat(reopened.distinctLiveResources("agent", "https://a.example", NOW))
                .isZero();
    }

    @Test
    void personTokenPendingRoundTripsThroughSql() {
        SqlPendingStore store =
                new SqlPendingStore(db.dataSource(), new SqlMissionState(db.dataSource()), "http://test.example", 600);
        PersonTokenRequest request = new PersonTokenRequest(
                "agent", Map.of("kty", "OKP"), "https://a.example", null, null, NOW + 600, "A", null, null, null);
        String pendingId = store.createPersonTokenPending(request, "user");

        PendingRecord record = store.getRecord(pendingId);
        assertThat(record.kind).isEqualTo("person_token");
        assertThat(record.personTokenRequest).isEqualTo(request);
        assertThat(record.ownerId).isEqualTo("user");
    }

    @Test
    void presentationsToAccessServersPersistWithoutDuplicates() {
        SqlPersonTokenLedger ledger = new SqlPersonTokenLedger(db.dataSource());
        ledger.recordPresentation("pt-1", "https://as-b.example/");
        ledger.recordPresentation("pt-1", "https://as-b.example");
        ledger.recordPresentation("pt-1", "https://as-a.example");

        assertThat(new SqlPersonTokenLedger(db.dataSource()).presentedTo("pt-1"))
                .containsExactly("https://as-a.example", "https://as-b.example");
        assertThat(ledger.presentedTo("pt-2")).isEmpty();
    }

    @Test
    void liveTokensForAnAgentExcludeExpiredAndOtherAgents() {
        SqlPersonTokenLedger ledger = new SqlPersonTokenLedger(db.dataSource());
        ledger.recordIssued(new PersonTokenLedger.Issued("live", "agent", "user", "https://a.example", "s", NOW + 60));
        ledger.recordIssued(new PersonTokenLedger.Issued("old", "agent", "user", "https://a.example", "s", NOW - 1));
        ledger.recordIssued(
                new PersonTokenLedger.Issued("other", "agent-2", "user", "https://a.example", "s", NOW + 60));

        assertThat(ledger.liveFor("agent", NOW))
                .extracting(PersonTokenLedger.Issued::jti)
                .containsExactly("live");
    }
}
