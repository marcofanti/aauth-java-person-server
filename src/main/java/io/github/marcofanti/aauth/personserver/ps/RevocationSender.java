package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Outbound revocation (§11.12.1, PS-113): the PS signs as a server and posts {@code {jti, exp}}
 * to the recipient's {@code revocation_endpoint}, discovered from its metadata. An AS's 200 may
 * carry a {@code downstream} array (PS-114), which is logged; the PS reports nothing upstream.
 */
public final class RevocationSender {

    /** Terminal outcome of one downstream revocation (§11.12.3). */
    public enum Outcome {
        REVOKED,
        REVOCATION_UNSUPPORTED,
        REVOCATION_UNAVAILABLE
    }

    /** Metadata document of a resource, which revokes person and auth tokens it accepted. */
    public static final String RESOURCE_METADATA = "aauth-resource.json";
    /** Metadata document of a PS, where an agent provider revokes agent tokens (§11.12.2). */
    public static final String PERSON_METADATA = "aauth-person.json";
    /** Metadata document of an AS, which revokes person tokens the PS presented to it. */
    public static final String ACCESS_METADATA = "aauth-access.json";

    private static final Logger log = LoggerFactory.getLogger(RevocationSender.class);

    private final ServerHttp http;

    public RevocationSender(ServerHttp http) {
        this.http = http;
    }

    /**
     * Revoke {@code jti} at {@code recipient}, whose {@code revocation_endpoint} is read from its
     * {@code metadata} document; never throws, every failure is an outcome.
     */
    public Outcome send(String recipient, String metadata, String jti, long exp) {
        String endpoint;
        try {
            endpoint = revocationEndpoint(recipient, metadata);
        } catch (IllegalArgumentException e) {
            log.info("revocation metadata for {} unavailable: {}", recipient, e.getMessage());
            return Outcome.REVOCATION_UNAVAILABLE;
        }
        if (endpoint == null) {
            return Outcome.REVOCATION_UNSUPPORTED;
        }
        try {
            return outcome(http.post(endpoint, Map.of("jti", jti, "exp", exp)));
        } catch (IOException | IllegalArgumentException e) {
            log.info("revocation at {} failed: {}", endpoint, e.getMessage());
            return Outcome.REVOCATION_UNAVAILABLE;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Outcome.REVOCATION_UNAVAILABLE;
        }
    }

    private static String revocationEndpoint(String recipient, String metadata) {
        Map<String, Object> document =
                SyncHttp.fetchJson(MissionUtils.stripTrailingSlash(recipient) + "/.well-known/" + metadata);
        return document.get("revocation_endpoint") instanceof String uri && !uri.isBlank() ? uri : null;
    }

    /** §11.12.3: 200 is recorded, {@code unsupported_iss} is unsupported, anything else unavailable. */
    private static Outcome outcome(HttpResponse<String> response) {
        String body = response.body() == null ? "" : response.body().strip();
        if (response.statusCode() == 200) {
            if (body.isEmpty()) {
                return Outcome.REVOKED;
            }
            if (!isJsonObject(body)) {
                return Outcome.REVOCATION_UNAVAILABLE;
            }
            if (Json.readMap(body).get("downstream") instanceof List<?> downstream && !downstream.isEmpty()) {
                log.info("revocation at {} reported downstream outcomes {}", response.uri(), downstream);
            }
            return Outcome.REVOKED;
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
