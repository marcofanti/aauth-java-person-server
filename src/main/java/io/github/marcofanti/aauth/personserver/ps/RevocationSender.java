package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Outbound revocation (§11.12.1, PS-113): the PS signs as a server under the {@code jwks_uri}
 * scheme and posts {@code {jti, exp}} to the recipient's {@code revocation_endpoint}, discovered
 * from its {@code aauth-resource.json} metadata.
 */
public final class RevocationSender {

    /** Terminal outcome of one downstream revocation (§11.12.3). */
    public enum Outcome {
        REVOKED,
        REVOCATION_UNSUPPORTED,
        REVOCATION_UNAVAILABLE
    }

    private static final Logger log = LoggerFactory.getLogger(RevocationSender.class);
    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String JSON = "application/json";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final String psOrigin;
    private final PsSigningService signing;

    public RevocationSender(String psOrigin, PsSigningService signing) {
        this.psOrigin = MissionUtils.stripTrailingSlash(psOrigin);
        this.signing = signing;
    }

    /** Revoke {@code jti} at {@code recipient}; never throws, every failure is an outcome. */
    public Outcome send(String recipient, String jti, long exp) {
        String endpoint;
        try {
            endpoint = revocationEndpoint(recipient);
        } catch (IllegalArgumentException e) {
            log.info("revocation metadata for {} unavailable: {}", recipient, e.getMessage());
            return Outcome.REVOCATION_UNAVAILABLE;
        }
        if (endpoint == null) {
            return Outcome.REVOCATION_UNSUPPORTED;
        }
        try {
            return outcome(post(endpoint, jti, exp));
        } catch (IOException | IllegalArgumentException e) {
            log.info("revocation at {} failed: {}", endpoint, e.getMessage());
            return Outcome.REVOCATION_UNAVAILABLE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Outcome.REVOCATION_UNAVAILABLE;
        }
    }

    private static String revocationEndpoint(String recipient) {
        Map<String, Object> metadata =
                SyncHttp.fetchJson(MissionUtils.stripTrailingSlash(recipient) + "/.well-known/aauth-resource.json");
        return metadata.get("revocation_endpoint") instanceof String uri && !uri.isBlank() ? uri : null;
    }

    private HttpResponse<String> post(String endpoint, String jti, long exp) throws IOException, InterruptedException {
        byte[] body = Json.write(Map.of("jti", jti, "exp", exp)).getBytes(StandardCharsets.UTF_8);
        URI uri = URI.create(endpoint);
        Map<String, String> signed = RequestSigner.sign(SignRequest.builder("POST", endpoint)
                .headers(Map.of("Host", uri.getRawAuthority(), "Content-Type", JSON))
                .body(body)
                .keyPair(signing.keyPair())
                .scheme(new SignatureScheme.JwksUri(psOrigin, "aauth-person.json", signing.kid()))
                .additionalComponents(BODY_COMPONENTS)
                .build());
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(TIMEOUT)
                .header("Content-Type", JSON)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        signed.forEach(request::header);
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** §11.12.3: 200 is recorded, {@code unsupported_iss} is unsupported, anything else unavailable. */
    private static Outcome outcome(HttpResponse<String> response) {
        String body = response.body() == null ? "" : response.body().strip();
        if (response.statusCode() == 200) {
            return body.isEmpty() || isJsonObject(body) ? Outcome.REVOKED : Outcome.REVOCATION_UNAVAILABLE;
        }
        if (response.statusCode() == 403
                && isJsonObject(body)
                && "unsupported_iss".equals(Json.readMap(body).get("error"))) {
            return Outcome.REVOCATION_UNSUPPORTED;
        }
        return Outcome.REVOCATION_UNAVAILABLE;
    }

    private static boolean isJsonObject(String body) {
        try {
            Json.readMap(body);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
