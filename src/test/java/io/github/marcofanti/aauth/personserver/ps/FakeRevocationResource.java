package io.github.marcofanti.aauth.personserver.ps;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/** A resource on a real socket that publishes a revocation endpoint and records what it receives. */
public final class FakeRevocationResource implements AutoCloseable {

    /** One revocation received: the request target, its headers (lowercased) and its body. */
    public record Received(String uri, Map<String, String> headers, byte[] body) {
        public Map<String, Object> json() {
            return Json.readMap(new String(body, StandardCharsets.UTF_8));
        }
    }

    private final HttpServer server;
    private final List<Received> received = new CopyOnWriteArrayList<>();
    private volatile boolean advertiseEndpoint = true;
    private volatile int status = 200;
    private volatile String responseBody = "";

    public FakeRevocationResource() {
        this("aauth-resource.json");
    }

    /** A recipient publishing {@code revocation_endpoint} in {@code metadataDocument} (e.g. a PS's). */
    public FakeRevocationResource(String metadataDocument) {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/.well-known/" + metadataDocument, this::metadata);
        server.createContext("/revoke", this::revoke);
        server.start();
        HostRoutes.register(origin(), "http://127.0.0.1:" + server.getAddress().getPort());
    }

    /**
     * The fake's draft-11 identifier: a port-less HTTPS origin, routed to its local socket via
     * {@link HostRoutes}.
     */
    public String origin() {
        return "https://rs" + server.getAddress().getPort() + ".example";
    }

    public List<Received> received() {
        return received;
    }

    public FakeRevocationResource withoutEndpoint() {
        advertiseEndpoint = false;
        return this;
    }

    public FakeRevocationResource answering(int newStatus, String body) {
        status = newStatus;
        responseBody = body;
        return this;
    }

    private void metadata(HttpExchange exchange) throws IOException {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("issuer", origin());
        if (advertiseEndpoint) {
            metadata.put("revocation_endpoint", origin() + "/revoke");
        }
        respond(exchange, 200, Json.write(metadata));
    }

    private void revoke(HttpExchange exchange) throws IOException {
        Map<String, String> headers = new LinkedHashMap<>();
        exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.getFirst()));
        received.add(new Received(
                origin() + exchange.getRequestURI(),
                headers,
                exchange.getRequestBody().readAllBytes()));
        respond(exchange, status, responseBody);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (!body.isEmpty()) {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
        }
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
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
