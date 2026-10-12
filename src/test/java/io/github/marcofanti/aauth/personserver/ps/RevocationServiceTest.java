package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender.Outcome;
import io.github.marcofanti.aauth.personserver.ps.RevocationService.CallerKind;
import io.github.marcofanti.aauth.personserver.ps.RevocationService.Downstream;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/** The revocation cascade (§11.12.4) over in-memory stores, with a recording sender. */
class RevocationServiceTest {

    private static final String PS = "https://ps.example";
    private static final String AP = "https://ap.example";
    private static final String RS = "https://rs.example";
    private static final String AGENT = "aauth:planner@ap.example";
    private static final long NOW = Instant.now().getEpochSecond();

    private final RevocationStore revocations = new MemoryRevocationStore();
    private final PersonTokenLedger personTokens = new MemoryPersonTokenLedger();
    private final IssuedTokenStore authTokens = new MemoryIssuedTokenStore();
    private final MemoryPendingStore pending = new MemoryPendingStore(new PsBackend(), PS, 600);
    private final List<String> sent = new CopyOnWriteArrayList<>();
    private RevocationService service = service(Outcome.REVOKED);

    private RevocationService service(Outcome outcome) {
        return new RevocationService(
                PS, new RevocationService.Deps(revocations, personTokens, authTokens, pending, (recipient, token) -> {
                    sent.add(token.jti() + "@" + recipient + "#" + token.exp());
                    return outcome;
                }));
    }

    private static String unsignedJwt(Map<String, Object> claims) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String payload = io.github.marcofanti.aauth.personserver.Json.write(claims);
        return encoder.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + "."
                + encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    private void issueAuthToken(String agent, String jti, long exp) {
        authTokens.recordIssued(new IssuedTokenStore.IssuedToken(
                unsignedJwt(Map.of("jti", jti)),
                agent,
                "user",
                RS,
                "scope",
                null,
                "autonomous",
                Instant.ofEpochSecond(exp)));
    }

    @Test
    void agentTokenRevocationCascadesToEveryLiveTokenIssuedToThatAgent() {
        revocations.recordAgentToken(AP, "agent-jti", AGENT, NOW + 600);
        personTokens.recordIssued(new PersonTokenLedger.Issued("pt-1", AGENT, "user", RS, "sub", NOW + 300));
        personTokens.recordIssued(new PersonTokenLedger.Issued("pt-old", AGENT, "user", RS, "sub", NOW - 1));
        personTokens.recordIssued(
                new PersonTokenLedger.Issued("pt-other", "aauth:other@ap", "user", RS, "s", NOW + 300));
        issueAuthToken(AGENT, "at-1", NOW + 200);
        issueAuthToken(AGENT, "at-old", NOW - 1);
        issueAuthToken("aauth:other@ap", "at-other", NOW + 200);

        List<Downstream> outcomes = service.revoke(AP, CallerKind.AGENT_PROVIDER, "agent-jti", NOW + 600);

        assertThat(revocations.isRevoked(AP, "agent-jti")).isTrue();
        assertThat(sent).containsExactlyInAnyOrder("pt-1@" + RS + "#" + (NOW + 300), "at-1@" + RS + "#" + (NOW + 200));
        assertThat(outcomes).extracting(Downstream::outcome).containsOnly(Outcome.REVOKED);
        assertThat(revocations.isRevoked(PS, "pt-1")).isTrue();
        assertThat(revocations.isRevoked(PS, "at-1")).isTrue();
        assertThat(revocations.isRevoked(PS, "pt-other")).isFalse();
        assertThat(revocations.isRevoked(PS, "at-other")).isFalse();
    }

    @Test
    void cascadeIsByAgentIdentityNotByTheRevokedToken() {
        revocations.recordAgentToken(AP, "agent-jti-1", AGENT, NOW + 600);
        revocations.recordAgentToken(AP, "agent-jti-2", AGENT, NOW + 600);
        personTokens.recordIssued(new PersonTokenLedger.Issued("pt-1", AGENT, "user", RS, "sub", NOW + 300));

        service.revoke(AP, CallerKind.AGENT_PROVIDER, "agent-jti-2", NOW + 600);

        assertThat(sent).hasSize(1);
        assertThat(revocations.isRevoked(AP, "agent-jti-1")).isFalse();
    }

    @Test
    void unseenAgentTokenIsRecordedWithNothingDownstream() {
        assertThat(service.revoke(AP, CallerKind.AGENT_PROVIDER, "never-seen", NOW + 60))
                .isEmpty();
        assertThat(revocations.isRevoked(AP, "never-seen")).isTrue();
        assertThat(sent).isEmpty();
    }

    @Test
    void repeatingARevocationRetriesDownstream() {
        service = service(Outcome.REVOCATION_UNAVAILABLE);
        revocations.recordAgentToken(AP, "agent-jti", AGENT, NOW + 600);
        personTokens.recordIssued(new PersonTokenLedger.Issued("pt-1", AGENT, "user", RS, "sub", NOW + 300));

        assertThat(service.revoke(AP, CallerKind.AGENT_PROVIDER, "agent-jti", NOW + 600))
                .extracting(Downstream::outcome)
                .containsExactly(Outcome.REVOCATION_UNAVAILABLE);
        service.revoke(AP, CallerKind.AGENT_PROVIDER, "agent-jti", NOW + 600);
        assertThat(sent).hasSize(2);
    }

    @Test
    void resourceTokenRevocationEndsThePendingStartedForIt() {
        String pendingId =
                pending.createPending(TokenRequest.builder(AGENT, "rt").build());
        pending.getRecord(pendingId).verifiedResourceClaims = Map.of("iss", RS, "jti", "rt-1");
        String unrelated =
                pending.createPending(TokenRequest.builder(AGENT, "rt2").build());
        pending.getRecord(unrelated).verifiedResourceClaims = Map.of("iss", RS, "jti", "rt-2");

        assertThat(service.revoke(RS, CallerKind.RESOURCE, "rt-1", NOW + 60)).isEmpty();

        assertThat(revocations.isRevoked(RS, "rt-1")).isTrue();
        PendingDeniedException denied =
                catchThrowableOfType(PendingDeniedException.class, () -> pending.getPending(pendingId, false));
        assertThat(denied.reason()).isEqualTo("revoked");
        assertThat(pending.openPendingForResourceToken(RS, "rt-2")).containsExactly(unrelated);
        assertThat(sent).isEmpty();
    }

    @Test
    void anExpBeyondAnyTokenLifetimeIsInvalid() {
        ProblemError error = catchThrowableOfType(
                ProblemError.class, () -> service.revoke(AP, CallerKind.AGENT_PROVIDER, "t", NOW + 90_000));
        assertThat(error.status()).isEqualTo(400);
        assertThat(error.error()).isEqualTo("invalid_request");
        assertThat(revocations.isRevoked(AP, "t")).isFalse();
    }

    @Test
    void oneIssuerIsRateLimitedWithRetryAfter() {
        for (int i = 0; i < 100; i++) {
            service.revoke(RS, CallerKind.RESOURCE, "rt-" + i, NOW + 60);
        }
        ProblemError error = catchThrowableOfType(
                ProblemError.class, () -> service.revoke(RS, CallerKind.RESOURCE, "rt-over", NOW + 60));
        assertThat(error.status()).isEqualTo(429);
        assertThat(error.error()).isEqualTo(ProblemError.RATE_LIMITED);
        assertThat(error.retryAfter()).isBetween(1, 60);
        assertThat(revocations.isRevoked(RS, "rt-over")).isFalse();

        assertThat(service.revoke("https://other-rs.example", CallerKind.RESOURCE, "rt", NOW + 60))
                .isEmpty();
    }
}
