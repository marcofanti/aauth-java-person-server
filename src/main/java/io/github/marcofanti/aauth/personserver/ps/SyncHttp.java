package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Synchronous JSON HTTP fetch for JWKS / metadata discovery, through {@link Egress}. */
public final class SyncHttp {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private SyncHttp() {}

    /** GET JSON from {@code url}; refused unless {@link Egress} admits it. */
    public static Map<String, Object> fetchJson(String url) {
        HttpRequest request = HttpRequest.newBuilder(Egress.target(url))
                .header("Accept", "application/json")
                .timeout(TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = CLIENT.send(request, Egress.cappedBody());
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to fetch " + url + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalArgumentException("Interrupted fetching " + url, e);
        }
        if (response.statusCode() / 100 != 2) {
            throw new IllegalArgumentException("HTTP " + response.statusCode() + " fetching " + url);
        }
        return Json.readMap(response.body());
    }

    /** Fetch {@code {identifier}/.well-known/{metadataFilename}} and then the {@code jwks_uri} document. */
    public static Map<String, Object> discoverJwksViaMetadata(String identifier, String metadataFilename) {
        String metaUrl = MissionUtils.stripTrailingSlash(identifier) + "/.well-known/" + metadataFilename;
        Map<String, Object> meta = fetchJson(metaUrl);
        Object jwksUri = meta.get("jwks_uri");
        if (!(jwksUri instanceof String uri) || uri.isEmpty()) {
            throw new IllegalArgumentException("No jwks_uri in metadata from " + metaUrl);
        }
        Map<String, Object> jwks = fetchJson(uri);
        if (!(jwks.get("keys") instanceof List)) {
            throw new IllegalArgumentException("Invalid JWKS from " + uri);
        }
        return jwks;
    }
}
