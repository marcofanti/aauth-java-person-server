package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.FakeAccessServer.Answer;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The federation loop is bounded however the AS answers (§9.1.2). */
class HttpAsFederatorTest {

    private static final String PS = "https://ps.example";

    private final FakeAccessServer as = new FakeAccessServer();
    private final PsSigningService signing = new PsSigningService(null);
    private final HttpAsFederator federator = new HttpAsFederator(
            new FakeAsFederator(),
            ServerHttp.personServer(PS, signing),
            new MemoryPersonTokenLedger(),
            Duration.ofSeconds(1));

    @AfterEach
    void stop() {
        as.close();
    }

    private TokenRequest request() {
        String person = PersonTokens.create(PersonTokens.Spec.builder(
                        PS,
                        "https://rs.example",
                        "sub",
                        Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), "eph"),
                        signing.keyPair().getPrivate(),
                        signing.kid())
                .agentExp(Instant.now().getEpochSecond() + 600)
                .build());
        return TokenRequest.builder("aauth:agent@ap.example", "rt")
                .draft11(new TokenRequest.Draft11(person, null, "agent-token"))
                .build();
    }

    @Test
    void anAccessServerThatAsksForClaimsForeverHitsTheDeadline() {
        as.answer(request -> new Answer(
                202,
                Map.of("Location", "/pending/1", "AAuth-Requirement", "requirement=claims"),
                Json.write(Map.of("status", "pending", "required_claims", List.of("email")))));
        long started = System.nanoTime();

        ProblemError error = catchThrowableOfType(
                ProblemError.class,
                () -> federator.federateDraft11(request(), Map.of("aud", as.origin(), "iss", "https://rs.example")));

        assertThat(error.error()).isEqualTo(ProblemError.AS_UNREACHABLE);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(5));
    }
}
