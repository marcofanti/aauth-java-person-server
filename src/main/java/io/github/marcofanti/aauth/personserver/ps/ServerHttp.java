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
import java.security.KeyPair;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Requests a server makes in its own right (§11.3.2), through {@link Egress}: signed under the
 * {@code jwks_uri} scheme
 * with {@code id} = its issuer and {@code dwk} = its metadata document, covering
 * {@code content-digest} and {@code content-type} whenever there is a body (§11.3.3).
 */
public final class ServerHttp {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final String JSON = "application/json";
    private static final List<String> BODY_COMPONENTS = List.of("content-type", "content-digest");

    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private final String issuer;
    private final String dwk;
    private final KeyPair keyPair;
    private final String kid;

    public ServerHttp(String issuer, String dwk, KeyPair keyPair, String kid) {
        this.issuer = MissionUtils.stripTrailingSlash(issuer);
        this.dwk = dwk;
        this.keyPair = keyPair;
        this.kid = kid;
    }

    /** The Person Server signing as itself ({@code dwk=aauth-person.json}). */
    public static ServerHttp personServer(String psOrigin, PsSigningService signing) {
        return new ServerHttp(psOrigin, "aauth-person.json", signing.keyPair(), signing.kid());
    }

    /** Signed JSON POST. */
    public HttpResponse<String> post(String url, Map<String, Object> body) throws IOException, InterruptedException {
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = new LinkedHashMap<>(signedHeaders("POST", url, bytes));
        headers.put("Content-Type", JSON);
        return send(
                HttpRequest.newBuilder(Egress.target(url)).POST(HttpRequest.BodyPublishers.ofByteArray(bytes)),
                headers);
    }

    /**
     * Unsigned GET of a JSON object (metadata, JWKS) with the same bounded timeouts and no
     * redirects, so a slow or hostile peer cannot hold a thread for long.
     *
     * @throws IllegalArgumentException when the peer is unreachable, answers non-2xx, or sends no JSON object
     */
    public Map<String, Object> fetchJson(String url) {
        HttpResponse<String> response;
        try {
            response = client.send(
                    HttpRequest.newBuilder(Egress.target(url))
                            .header("Accept", JSON)
                            .timeout(TIMEOUT)
                            .GET()
                            .build(),
                    Egress.cappedBody());
        } catch (IOException e) {
            throw new IllegalArgumentException("failed to fetch " + url + ": " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalArgumentException("interrupted fetching " + url, e);
        }
        if (response.statusCode() / 100 != 2) {
            throw new IllegalArgumentException("HTTP " + response.statusCode() + " fetching " + url);
        }
        return Json.readMap(response.body());
    }

    /** Signed GET with no body (pending-URL polling, §11.8). */
    public HttpResponse<String> get(String url) throws IOException, InterruptedException {
        return send(HttpRequest.newBuilder(Egress.target(url)).GET(), signedHeaders("GET", url, null));
    }

    private Map<String, String> signedHeaders(String method, String url, byte[] body) {
        URI uri = URI.create(url);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Host", uri.getRawAuthority());
        SignRequest.Builder request =
                SignRequest.builder(method, url).keyPair(keyPair).scheme(new SignatureScheme.JwksUri(issuer, dwk, kid));
        if (body != null) {
            headers.put("Content-Type", JSON);
            request.body(body).additionalComponents(BODY_COMPONENTS);
        }
        return RequestSigner.sign(request.headers(headers).build());
    }

    private HttpResponse<String> send(HttpRequest.Builder request, Map<String, String> headers)
            throws IOException, InterruptedException {
        headers.forEach((name, value) -> {
            if (!"Host".equalsIgnoreCase(name)) {
                request.header(name, value);
            }
        });
        return client.send(request.timeout(TIMEOUT).build(), Egress.cappedBody());
    }
}
