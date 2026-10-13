package io.github.marcofanti.aauth.personserver.ps;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * An access server on a real socket (§9.1): publishes {@code aauth-access.json} and a JWKS, and
 * answers the PS's token requests and pending-URL calls through a replaceable handler.
 */
public final class FakeAccessServer implements AutoCloseable {

    /** One request the AS received. */
    public record Received(String method, String path, Map<String, String> headers, byte[] body) {
        public Map<String, Object> json() {
            return Json.readMap(new String(body, StandardCharsets.UTF_8));
        }

        public String uri(String origin) {
            return origin + path;
        }
    }

    /** What the AS answers. */
    public record Answer(int status, Map<String, String> headers, String body) {
        public static Answer json(int status, Map<String, Object> body) {
            return new Answer(status, Map.of("Content-Type", "application/json"), Json.write(body));
        }
    }

    public static final String KID = "fake-as-kid";

    private final HttpServer server;
    private final KeyPair key = KeyPairs.generateEd25519();
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private volatile Function<Received, Answer> handler = this::issue;

    public FakeAccessServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/.well-known/aauth-access.json", exchange -> respond(exchange, metadata()));
        server.createContext(
                "/jwks",
                exchange -> respond(
                        exchange, Answer.json(200, Map.of("keys", List.of(Jwk.publicKeyToJwk(key.getPublic(), KID))))));
        server.createContext("/", this::handle);
        server.start();
        HostRoutes.register(origin(), "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /**
     * The fake's draft-11 identifier: a port-less HTTPS origin, routed to its local socket via
     * {@link HostRoutes}.
     */
    public String origin() {
        return "https://as" + server.getAddress().getPort() + ".example";
    }

    public KeyPair key() {
        return key;
    }

    public List<Received> received() {
        return received;
    }

    /** Replace how the AS answers requests to its token endpoint and pending URLs. */
    public void answer(Function<Received, Answer> newHandler) {
        received.clear();
        handler = newHandler;
    }

    /** Restore the default: issue an auth token for every token request. */
    public void reset() {
        answer(this::issue);
    }

    private Answer metadata() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", origin());
        metadata.put("auth_token_endpoint", origin() + "/auth-token");
        metadata.put("jwks_uri", origin() + "/jwks");
        metadata.put("revocation_endpoint", origin() + "/revoke");
        return Answer.json(200, metadata);
    }

    /** A well-formed §9.4.1 auth token for the request's resource, person, agent and presented token. */
    public Answer issue(Received request) {
        return Answer.json(200, Map.of("auth_token", authToken(request, Map.of()), "expires_in", 600));
    }

    /**
     * The auth token {@link #issue} would mint, with {@code overrides} applied to its claims
     * ({@code cnf_jwk} replaces the agent key it is bound to).
     */
    public String authToken(Received tokenRequest, Map<String, Object> overrides) {
        Map<String, Object> body = tokenRequest.json();
        Map<String, Object> resource =
                Jwts.parse((String) body.get("resource_token")).payload();
        Map<String, Object> presented =
                Jwts.parse((String) body.get("presented_token")).payload();
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) ((Map<String, Object>)
                        Jwts.parse((String) body.get("agent_token")).payload().get("cnf"))
                .get("jwk");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", resource.get("iss"));
        claims.put("sub", resource.get("sub"));
        claims.put("scope", resource.get("scope"));
        claims.put("exp", ((Number) presented.get("exp")).longValue());
        claims.putAll(overrides);
        return AuthTokens.create(AuthTokens.Spec.builder(
                        origin(), (String) claims.get("aud"), (String) claims.get("sub"), (String) resource.get("ps"))
                .cnfJwk(claims.get("cnf_jwk") instanceof Map<?, ?> other ? asJwk(other) : cnf)
                .signingKey(key.getPrivate(), KID)
                .scope((String) claims.get("scope"))
                .exp(((Number) claims.get("exp")).longValue())
                .bounds(((Number) claims.get("exp")).longValue(), ((Number) claims.get("exp")).longValue())
                .dwk("aauth-access.json")
                .build());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asJwk(Map<?, ?> jwk) {
        return (Map<String, Object>) jwk;
    }

    private void handle(HttpExchange exchange) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        exchange.getRequestHeaders()
                .forEach((name, values) -> headers.put(name.toLowerCase(java.util.Locale.ROOT), values.getFirst()));
        Received request = new Received(
                exchange.getRequestMethod(),
                exchange.getRequestURI().toString(),
                headers,
                exchange.getRequestBody().readAllBytes());
        received.add(request);
        respond(exchange, handler.apply(request));
    }

    private static void respond(HttpExchange exchange, Answer answer) throws IOException {
        byte[] bytes = answer.body().getBytes(StandardCharsets.UTF_8);
        answer.headers().forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
        exchange.sendResponseHeaders(answer.status(), bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
