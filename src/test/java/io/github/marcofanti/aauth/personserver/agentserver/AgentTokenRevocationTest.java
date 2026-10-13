package io.github.marcofanti.aauth.personserver.agentserver;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.ps.FakeRevocationResource;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender.Outcome;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** An agent provider revokes its agent tokens at the PS when a binding is revoked (§11.12.2). */
class AgentTokenRevocationTest {

    private static final String ISSUER = "https://agents.example";

    private final FakeRevocationResource ps = new FakeRevocationResource("aauth-person.json");
    private final AsSigningService signing = new AsSigningService(ISSUER, null, null, 3600, ps.origin());
    private final AgentTokenRevocation revocation =
            AsContainer.tokenRevocation(ISSUER, signing, new MemoryIssuedAgentTokenStore());

    @AfterEach
    void stop() {
        ps.close();
    }

    private String issue(String agentId) {
        String token = signing.createAgentToken(
                agentId, Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), "eph"), null);
        revocation.record(token);
        return token;
    }

    private static List<Outcome> join(List<CompletableFuture<Outcome>> futures) {
        return futures.stream().map(CompletableFuture::join).toList();
    }

    @Test
    void revokingABindingRevokesThatAgentsLiveTokensAtItsPs() {
        String token = issue("aauth:a@agents.example");
        issue("aauth:b@agents.example");

        assertThat(join(revocation.revokeAll("aauth:a@agents.example"))).containsExactly(Outcome.REVOKED);

        FakeRevocationResource.Received received = ps.received().getFirst();
        assertThat(received.json()).containsEntry("jti", Jwts.parse(token).claim("jti"));
        SignatureKeyHeader.Parsed key =
                SignatureKeyHeader.parse(received.headers().get("signature-key"));
        assertThat(key.params()).containsEntry("id", ISSUER).containsEntry("dwk", "aauth-agent.json");
        assertThat(SignatureVerifier.verify(VerifyRequest.builder("POST", received.uri())
                        .headers(received.headers())
                        .body(received.body())
                        .signatureHeaders(
                                received.headers().get("signature-input"),
                                received.headers().get("signature"),
                                received.headers().get("signature-key"))
                        .jwksFetcher((id, dwk, kid) -> ISSUER.equals(id) ? signing.getJwks() : null)
                        .build()))
                .isTrue();
    }

    @Test
    void anAgentWithNoLiveTokensRevokesNothing() {
        issue("aauth:a@agents.example");
        assertThat(revocation.revokeAll("aauth:other@agents.example")).isEmpty();
    }

    @Test
    void tokensWithoutAPsAreNotRecorded() {
        AsSigningService noPs = new AsSigningService(ISSUER, null, null, 3600, null);
        revocation.record(noPs.createAgentToken(
                "aauth:a@agents.example",
                Jwk.publicKeyToJwk(KeyPairs.generateEd25519().getPublic(), "eph"),
                null));
        assertThat(revocation.revokeAll("aauth:a@agents.example")).isEmpty();
    }

    @Test
    void expiredTokensAreDropped() {
        // The library will not mint an expired token; record() only reads the claims it needs.
        String token = Jwts.encode(
                Map.of(
                        "iss",
                        ISSUER,
                        "sub",
                        "aauth:a@agents.example",
                        "jti",
                        "expired-1",
                        "ps",
                        ps.origin(),
                        "exp",
                        java.time.Instant.now().getEpochSecond() - 1),
                signing.keyPair().getPrivate(),
                signing.kid(),
                "aa-agent+jwt");
        revocation.record(token);
        assertThat(revocation.revokeAll("aauth:a@agents.example")).isEmpty();
    }
}
