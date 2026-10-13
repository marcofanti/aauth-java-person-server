package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.agentserver.AgentTokenRevocation;
import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.AsSigningService;
import io.github.marcofanti.aauth.personserver.agentserver.IssuedAgentTokenStore;
import io.github.marcofanti.aauth.personserver.agentserver.IssuedAgentTokenStore.Issued;
import io.github.marcofanti.aauth.personserver.agentserver.MemoryIssuedAgentTokenStore;
import io.github.marcofanti.aauth.personserver.ps.FakeRevocationResource;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender.Outcome;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The Agent Server's issued-token records behave the same in memory and in SQL, and survive a restart. */
class SqlIssuedAgentTokenStoreTest {

    private static final String ISSUER = "https://agents.example";

    @TempDir
    Path tempDir;

    private DbHolder db;

    @BeforeEach
    void setUp() {
        db = DbHolder.fromUrl("sqlite:///" + tempDir.resolve("issued.db"));
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    private void forBoth(Consumer<IssuedAgentTokenStore> check) {
        check.accept(new MemoryIssuedAgentTokenStore());
        check.accept(new SqlAgentServerStores.IssuedAgentTokens(db.dataSource()));
    }

    @Test
    void liveTokensAreListedPerAgentAndTheFirstRecordWins() {
        forBoth(store -> {
            store.record(new Issued("t-1", "aauth:a@agents.example", "https://ps.example", 200));
            store.record(new Issued("t-1", "aauth:other@agents.example", "https://ps.example", 200));
            store.record(new Issued("t-2", "aauth:b@agents.example", "https://ps.example", 200));

            assertThat(store.liveFor("aauth:a@agents.example", 100))
                    .containsExactly(new Issued("t-1", "aauth:a@agents.example", "https://ps.example", 200));
            assertThat(store.liveFor("aauth:other@agents.example", 100)).isEmpty();
            assertThat(store.liveFor("aauth:a@agents.example", 200)).isEmpty();
        });
    }

    @Test
    void purgingDropsOnlyExpiredRecords() {
        forBoth(store -> {
            store.record(new Issued("old", "aauth:a@agents.example", "https://ps.example", 100));
            store.record(new Issued("new", "aauth:a@agents.example", "https://ps.example", 300));

            store.purgeExpired(100);

            assertThat(store.liveFor("aauth:a@agents.example", 0))
                    .extracting(Issued::jti)
                    .containsExactly("new");
        });
    }

    @Test
    void tokensIssuedBeforeARestartAreStillRevoked() {
        try (FakeRevocationResource ps = new FakeRevocationResource("aauth-person.json")) {
            AsSigningService signing = new AsSigningService(ISSUER, null, null, 3600, ps.origin());
            String token = signing.createAgentToken(
                    "aauth:a@agents.example",
                    Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), "eph"),
                    null);
            AsContainer.tokenRevocation(ISSUER, signing, new SqlAgentServerStores.IssuedAgentTokens(db.dataSource()))
                    .record(token);

            AgentTokenRevocation afterRestart = AsContainer.tokenRevocation(
                    ISSUER, signing, new SqlAgentServerStores.IssuedAgentTokens(db.dataSource()));

            assertThat(afterRestart.revokeAll("aauth:a@agents.example").stream().map(CompletableFuture::join))
                    .containsExactly(Outcome.REVOKED);
            assertThat(ps.received().getFirst().json())
                    .containsEntry("jti", Jwts.parse(token).claim("jti"));
        }
    }
}
