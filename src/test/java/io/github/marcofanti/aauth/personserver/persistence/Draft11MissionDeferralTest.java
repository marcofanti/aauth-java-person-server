package io.github.marcofanti.aauth.personserver.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.InteractionTerminalResult;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.personserver.ps.Draft11Missions;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.web.PsAuth.TokenAgentContext;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** With mission auto-approval off, a draft-11 proposal waits for the person (§8.1) in memory and SQL. */
class Draft11MissionDeferralTest {

    private static final String PS = "https://ps.example";
    private static final String AGENT_ID = "aauth:planner@agents.example";
    private static final String FLIGHTS = "https://flights.example";

    @TempDir
    Path tempDir;

    private DbHolder db;

    @BeforeEach
    void setUp() {
        db = DbHolder.fromUrl("sqlite:///" + tempDir.resolve("missions.db"));
    }

    @AfterEach
    void tearDown() {
        db.close();
    }

    private void forBoth(Consumer<PsContainer> check) {
        PsWiring.Options options = PsWiring.Options.builder(PS)
                .insecureDev(false)
                .signingKeyPath(null)
                .trustFile(null)
                .consentScopesFile(null)
                .autoApproveMission(false)
                .build();
        check.accept(PsWiring.buildMemoryPs(options));
        check.accept(PersistedWiring.buildPersistedPs(db.dataSource(), options));
    }

    private static TokenAgentContext agent() {
        Map<String, Object> cnf = Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), "eph");
        return new TokenAgentContext(
                AGENT_ID, Jwk.thumbprint(cnf), cnf, true, "https://agents.example", inOneHour(), null);
    }

    private static long inOneHour() {
        return Instant.now().getEpochSecond() + 3600;
    }

    private static DeferredResponse propose(PsContainer ps) {
        Draft11Missions.Outcome outcome = ps.draft11Missions()
                .propose(
                        agent(),
                        new Draft11Missions.Proposal(
                                "Plan a trip", List.of(new ToolSpec("BookFlight", "Book flights")), List.of(FLIGHTS)));
        assertThat(outcome).isInstanceOf(Draft11Missions.Outcome.Deferred.class);
        return ((Draft11Missions.Outcome.Deferred) outcome).deferred();
    }

    @Test
    void theProposalWaitsForThePersonWhoSeesWhatTheAgentProposed() {
        forBoth(ps -> {
            DeferredResponse deferred = propose(ps);

            assertThat(deferred.requirement()).isEqualTo(RequirementLevel.INTERACTION);
            assertThat(ps.mission().listAllMissions()).isEmpty();
            ConsentContext context = ps.userConsent().getConsentContext(deferred.code());
            assertThat(context.pendingKind()).isEqualTo("mission");
            assertThat(context.agentName()).isEqualTo(AGENT_ID);
            assertThat(context.proposalDescription()).isEqualTo("Plan a trip");
            assertThat(context.proposalTools()).containsExactly("BookFlight — Book flights");
            assertThat(context.proposalResources()).containsExactly(FLIGHTS);
        });
    }

    @Test
    void anApprovedProposalReachesTheAgentAsTheApprovalResponse() {
        forBoth(ps -> {
            DeferredResponse deferred = propose(ps);

            ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(true));

            InteractionTerminalResult result =
                    (InteractionTerminalResult) ps.tokenBroker().getPending(deferred.pendingId(), AGENT_ID);
            String s256 = (String) result.body().get("s256");
            byte[] blob = Base64.getUrlDecoder().decode((String) result.body().get("mission"));
            assertThat(new String(blob, java.nio.charset.StandardCharsets.UTF_8))
                    .contains("Plan a trip");
            assertThat(ps.mission().getMission(s256).state()).isEqualTo(MissionState.ACTIVE);
            @SuppressWarnings("unchecked")
            Map<String, String> personTokens =
                    (Map<String, String>) result.body().get("person_tokens");
            assertThat(Jwts.parse(personTokens.get(FLIGHTS)).claim("mission_s256"))
                    .isEqualTo(s256);
        });
    }

    @Test
    void aDeniedProposalEndsTheAgentsRequest() {
        forBoth(ps -> {
            DeferredResponse deferred = propose(ps);

            ps.userConsent().recordDecision(deferred.pendingId(), new UserDecision(false));

            PendingDeniedException denied = catchThrowableOfType(
                    PendingDeniedException.class, () -> ps.tokenBroker().getPending(deferred.pendingId(), AGENT_ID));
            assertThat(denied.reason()).isEqualTo("denied");
            assertThat(ps.mission().listAllMissions()).isEmpty();
        });
    }
}
