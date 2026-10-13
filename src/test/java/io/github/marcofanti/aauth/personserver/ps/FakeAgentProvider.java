package io.github.marcofanti.aauth.personserver.ps;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;

/**
 * An agent provider on a real socket ({@code aauth-agent.json} + JWKS) that mints agent tokens,
 * standing in for a call-chaining intermediary that is its own agent provider (§10.1.1.1).
 */
public final class FakeAgentProvider implements AutoCloseable {

    public static final String KID = "fake-ap-kid";

    private final HttpServer server;
    private final KeyPair key = KeyPairs.generateEd25519();

    public FakeAgentProvider() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext(
                "/.well-known/aauth-agent.json",
                exchange -> respond(exchange, Map.of("issuer", origin(), "jwks_uri", origin() + "/jwks")));
        server.createContext(
                "/jwks",
                exchange -> respond(exchange, Map.of("keys", List.of(Jwk.publicKeyToJwk(key.getPublic(), KID)))));
        server.start();
        HostRoutes.register(origin(), "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /**
     * The fake's draft-11 identifier: a port-less HTTPS origin, routed to its local socket via
     * {@link HostRoutes}.
     */
    public String origin() {
        return "https://ap" + server.getAddress().getPort() + ".example";
    }

    /** An agent token for {@code sub}, binding {@code agentKey}, valid for an hour. */
    public String agentToken(String sub, KeyPair agentKey, long exp) {
        return AgentTokens.create(AgentTokens.Spec.builder(
                        origin(), sub, Jwk.publicKeyToJwk(agentKey.getPublic(), "eph"), key.getPrivate(), KID)
                .exp(exp)
                .build());
    }

    private static void respond(HttpExchange exchange, Map<String, Object> body) throws IOException {
        byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
