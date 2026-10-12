package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.persistence.PendingSerde;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MemoryPersonTokenLedgerTest {

    private static final long NOW = Instant.now().getEpochSecond();

    private static PersonTokenLedger.Issued issued(String jti, String agent, String aud, long exp) {
        return new PersonTokenLedger.Issued(jti, agent, "user", aud, "sub-" + aud, exp);
    }

    @Test
    void liveResourceCountExcludesTheRequestedResourceAndExpiredTokens() {
        MemoryPersonTokenLedger ledger = new MemoryPersonTokenLedger();
        ledger.recordIssued(issued("1", "agent", "https://a.example", NOW + 600));
        ledger.recordIssued(issued("2", "agent", "https://a.example", NOW + 900));
        ledger.recordIssued(issued("3", "agent", "https://b.example", NOW + 600));
        ledger.recordIssued(issued("4", "agent", "https://c.example", NOW - 1));
        ledger.recordIssued(issued("5", "other", "https://d.example", NOW + 600));

        assertThat(ledger.distinctLiveResources("agent", "https://z.example", NOW))
                .isEqualTo(2);
        assertThat(ledger.distinctLiveResources("agent", "https://a.example/", NOW))
                .isEqualTo(1);
    }

    @Test
    void approvalsAreKeyedByPersonAndNormalizedResource() {
        MemoryPersonTokenLedger ledger = new MemoryPersonTokenLedger();
        ledger.approve("user", "https://a.example/");
        assertThat(ledger.isApproved("user", "https://a.example")).isTrue();
        assertThat(ledger.isApproved("someone-else", "https://a.example")).isFalse();
    }

    @Test
    void pendingSerdeRoundTripsAPersonTokenRequest() {
        PersonTokenRequest request = new PersonTokenRequest(
                "agent",
                Map.of("kty", "OKP", "crv", "Ed25519", "x", "abc"),
                "https://a.example",
                "mission-hash",
                "tenant-1",
                NOW + 600,
                "A Resource",
                "Does things",
                "person-token",
                "because");
        PendingRecord record = new PendingRecord("pid", "code", "person_token", Instant.now(), 600);
        record.personTokenRequest = request;

        PendingRecord restored = PendingSerde.recordFromDict(PendingSerde.recordToDict(record));
        assertThat(restored.personTokenRequest).isEqualTo(request);
    }
}
