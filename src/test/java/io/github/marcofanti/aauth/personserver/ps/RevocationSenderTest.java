package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.ps.RevocationSender.Outcome;
import io.github.marcofanti.aauth.signing.SignatureInputHeader;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Outbound revocation (§11.12.1, §11.12.3): signed as the PS, outcomes mapped to terminal values. */
class RevocationSenderTest {

    private static final String PS_ORIGIN = "https://ps.example";

    private final PsSigningService signing = new PsSigningService(null);
    private final RevocationSender sender = new RevocationSender(PS_ORIGIN, signing);
    private final FakeRevocationResource resource = new FakeRevocationResource();

    @AfterEach
    void stop() {
        resource.close();
    }

    @Test
    void postsJtiAndExpSignedAsThePersonServer() {
        assertThat(sender.send(resource.origin(), "pt-1", 1_900_000_000L)).isEqualTo(Outcome.REVOKED);

        FakeRevocationResource.Received request = resource.received().getFirst();
        assertThat(request.json()).containsEntry("jti", "pt-1").containsEntry("exp", 1_900_000_000);
        SignatureKeyHeader.Parsed key =
                SignatureKeyHeader.parse(request.headers().get("signature-key"));
        assertThat(key.scheme()).isEqualTo("jwks_uri");
        assertThat(key.params())
                .containsEntry("id", PS_ORIGIN)
                .containsEntry("dwk", "aauth-person.json")
                .containsEntry("kid", signing.kid());
        assertThat(SignatureInputHeader.parse(request.headers().get("signature-input"))
                        .components())
                .contains("content-type", "content-digest");
        boolean verified = SignatureVerifier.verify(VerifyRequest.builder("POST", request.uri())
                .headers(request.headers())
                .body(request.body())
                .signatureHeaders(
                        request.headers().get("signature-input"),
                        request.headers().get("signature"),
                        request.headers().get("signature-key"))
                .jwksFetcher((id, dwk, kid) -> PS_ORIGIN.equals(id) ? signing.getJwks() : null)
                .build());
        assertThat(verified).isTrue();
    }

    @Test
    void aJsonObjectBodyStillCountsAsRecorded() {
        resource.answering(200, "{\"downstream\":[]}");
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOKED);
    }

    @Test
    void anUnparseableBodyIsUnavailable() {
        resource.answering(200, "not json");
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNAVAILABLE);
    }

    @Test
    void noRevocationEndpointIsUnsupported() {
        resource.withoutEndpoint();
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNSUPPORTED);
        assertThat(resource.received()).isEmpty();
    }

    @Test
    void unsupportedIssIsUnsupported() {
        resource.answering(403, "{\"error\":\"unsupported_iss\"}");
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNSUPPORTED);
    }

    @Test
    void serverErrorsAndOtherRefusalsAreUnavailable() {
        resource.answering(503, "");
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNAVAILABLE);
        resource.answering(403, "{\"error\":\"other\"}");
        assertThat(sender.send(resource.origin(), "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNAVAILABLE);
    }

    @Test
    void anUnreachableRecipientIsUnavailable() {
        String gone = resource.origin();
        resource.close();
        assertThat(sender.send(gone, "pt-1", 1L)).isEqualTo(Outcome.REVOCATION_UNAVAILABLE);
    }

    @Test
    void signingInputCoversTheBody() {
        sender.send(resource.origin(), "pt-1", 1L);
        Map<String, String> headers = resource.received().getFirst().headers();
        assertThat(headers.get("content-digest")).startsWith("sha-256=");
    }
}
