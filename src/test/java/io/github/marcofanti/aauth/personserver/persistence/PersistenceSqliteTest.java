package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.PersonOps;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationOps;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.personserver.model.VerifiedRequest;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.TrustedAgentServer;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Port of {@code tests/test_persistence_sqlite.py}: one SQLite file backs PS + AS state,
 * and durable state (missions, logs, pendings, bindings, trust, issued tokens) survives a
 * container "restart" against the same file.
 */
class PersistenceSqliteTest {

    @TempDir
    Path tempDir;

    private String url() {
        return "sqlite:///" + tempDir.resolve("aauth.db");
    }

    private DbHolder holder() {
        return DbHolder.fromUrl(url());
    }

    private static PsContainer ps(DbHolder db) {
        return PersistedWiring.buildPersistedPs(
                db.dataSource(),
                PsWiring.Options.builder("http://test.example")
                        .signingKeyPath(null)
                        .trustFile(null)
                        .consentScopesFile(null)
                        .insecureDev(true)
                        .build());
    }

    private static AsContainer as(DbHolder db) {
        return PersistedWiring.buildPersistedAs(
                db.dataSource(),
                new AsContainer.MemoryOptions(
                        "http://test.example", "localhost", null, null, 86400, 3600, 60, "http://test.example"));
    }

    @Test
    void missionAndConsentFlowSurvivesRestart() {
        DeferredResponse deferred;
        Mission mission;
        try (DbHolder db = holder()) {
            PsContainer container = ps(db);
            mission = (Mission) container
                    .lifecycle()
                    .createMission(new MissionProposal("sql-agent", "Persist things.", java.util.List.of(), "user"));
            deferred = (DeferredResponse) container
                    .tokenBroker()
                    .requestToken(TokenRequest.builder("sql-agent", "fake-jwt")
                            .secureMode(false)
                            .mission(new io.github.marcofanti.aauth.personserver.model.MissionRef(
                                    mission.approver(), mission.s256()))
                            .build());
        }

        // "Restart": fresh containers over the same file.
        try (DbHolder db = holder()) {
            PsContainer container = ps(db);
            Mission reloaded = container.mission().getMission(mission.s256());
            assertThat(reloaded).isNotNull();
            assertThat(reloaded.state()).isEqualTo(MissionState.ACTIVE);
            assertThat(reloaded.blobBytes()).isEqualTo(mission.blobBytes());
            assertThat(container.mission().getMissionLog(mission.s256())).isNotEmpty();

            var context = container
                    .userConsent()
                    .getConsentContext(container.pendingStore().getInteractionCode(deferred.pendingId()));
            assertThat(context.mission().s256()).isEqualTo(mission.s256());
            container.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));
            PendingPollOutcome polled = container.tokenBroker().getPending(deferred.pendingId(), "sql-agent");
            assertThat(polled).isInstanceOf(AuthTokenResponse.class);

            // Terminal delivery is once-only even across loads.
            assertThatThrownBy(() -> container.tokenBroker().getPending(deferred.pendingId(), "sql-agent"))
                    .isInstanceOf(io.github.marcofanti.aauth.personserver.ps.NotFoundException.class);
        }
    }

    @Test
    void deniedConsentPersists() {
        try (DbHolder db = holder()) {
            PsContainer container = ps(db);
            DeferredResponse deferred = (DeferredResponse) container
                    .tokenBroker()
                    .requestToken(TokenRequest.builder("deny-agent", "fake-jwt")
                            .secureMode(false)
                            .build());
            container.userConsent().recordDecision(deferred.pendingId(), new UserDecision(false));
            PsContainer restarted = ps(db);
            assertThatThrownBy(() -> restarted.tokenBroker().getPending(deferred.pendingId(), "deny-agent"))
                    .isInstanceOf(PendingDeniedException.class);
        }
    }

    @Test
    void registrationsBindingsAndTokensSurviveRestart() {
        Map<String, Object> ephemeralPub = Map.of("kty", "OKP", "crv", "Ed25519", "x", "AAAA");
        Map<String, Object> stablePub = Map.of("kty", "OKP", "crv", "Ed25519", "x", "BBBB");
        String pendingId;
        String agentId;
        try (DbHolder db = holder()) {
            AsContainer container = as(db);
            RegistrationOps.RegisterResult result = RegistrationOps.handleRegister(
                    new VerifiedRequest("hwk", ephemeralPub), stablePub, "SQL Agent", container);
            pendingId = ((RegistrationOps.RegisterResult.Pending) result).pendingId();
            Map<String, Object> approved = PersonOps.handleApprove(pendingId, container, "localhost");
            agentId = String.valueOf(approved.get("agent_id"));
        }

        try (DbHolder db = holder()) {
            AsContainer container = as(db);
            RegistrationOps.PollResult polled =
                    RegistrationOps.handlePollPending(pendingId, new VerifiedRequest("hwk", ephemeralPub), container);
            assertThat(polled).isInstanceOf(RegistrationOps.PollResult.Token.class);
            assertThat(container.bindings().getByAgentId(agentId)).isNotNull();

            // Re-registration with the persisted stable key is immediate.
            RegistrationOps.RegisterResult again = RegistrationOps.handleRegister(
                    new VerifiedRequest("hwk", ephemeralPub), stablePub, "SQL Agent Renamed", container);
            assertThat(again).isInstanceOf(RegistrationOps.RegisterResult.Immediate.class);
            assertThat(container.bindings().getByAgentId(agentId).agentName()).isEqualTo("SQL Agent Renamed");
        }
    }

    @Test
    void trustRegistryAndIssuedTokensPersist() {
        try (DbHolder db = holder()) {
            PsContainer container = ps(db);
            container
                    .trustRegistry()
                    .add(new TrustedAgentServer(
                            "http://portal.uma.lab", "Portal", "http://portal.uma.lab/jwks", "fp", "now"));
            container
                    .issuedTokenStore()
                    .recordIssued(new io.github.marcofanti.aauth.personserver.ps.IssuedTokenStore.IssuedToken(
                            "tok", "agent", "user", "http://rs", "read", null, "autonomous", null));
        }
        try (DbHolder db = holder()) {
            PsContainer container = ps(db);
            assertThat(container.trustRegistry().isTrusted("http://portal.uma.lab/"))
                    .isTrue();
            assertThat(container.issuedTokenStore().listIssued()).hasSize(1);
            assertThat(container.trustRegistry().remove("http://portal.uma.lab"))
                    .isTrue();
        }
    }
}
