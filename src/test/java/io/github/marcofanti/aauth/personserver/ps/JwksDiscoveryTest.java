package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JWKS discovery over live sockets (JDK HttpServer), matching the library's test style. */
class JwksDiscoveryTest {

    private HttpServer server;
    private String origin;

    private static final Map<String, Object> JWKS = Map.of("keys", List.of(Map.of("kty", "OKP", "kid", "k1")));

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        origin = "http://127.0.0.1:" + server.getAddress().getPort();
        serveJson("/.well-known/aauth-resource.json", Map.of("jwks_uri", origin + "/jwks.json"));
        serveJson("/.well-known/aauth-agent.json", Map.of("jwks_uri", origin + "/jwks.json"));
        serveJson("/jwks.json", JWKS);
        serveJson("/.well-known/bad.json", Map.of("nope", true));
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private void serveJson(String path, Map<String, Object> body) {
        server.createContext(path, exchange -> {
            byte[] bytes = Json.write(body).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
    }

    @Test
    void discoverJwksViaMetadataFollowsJwksUri() {
        Map<String, Object> jwks = SyncHttp.discoverJwksViaMetadata(origin, "aauth-resource.json");
        assertThat(jwks).isEqualTo(JWKS);
    }

    @Test
    void discoveryFailsWithoutJwksUri() {
        assertThatThrownBy(() -> SyncHttp.discoverJwksViaMetadata(origin, "bad.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("jwks_uri");
    }

    @Test
    void fetchJsonRejectsHttpErrors() {
        assertThatThrownBy(() -> SyncHttp.fetchJson(origin + "/missing.json"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("404");
    }

    @Test
    void resourceResolverCachesAndReturnsNullOnFailure() {
        ResourceJwksResolver resolver = new ResourceJwksResolver();
        assertThat(resolver.apply(origin + "/")).isEqualTo(JWKS);
        assertThat(resolver.apply(origin)).isEqualTo(JWKS);
        assertThat(resolver.apply("http://127.0.0.1:1")).isNull();
    }

    @Test
    void agentResolverServesSelfTrustedAndRejectsUnknown() {
        MemoryAgentServerTrustRegistry trust = new MemoryAgentServerTrustRegistry(null);
        DeferredAgentSelfJwks selfJwks = new DeferredAgentSelfJwks();
        AgentServerJwksResolver resolver = new AgentServerJwksResolver("http://ps.uma.lab", trust, selfJwks);

        assertThatThrownBy(() -> resolver.apply("http://ps.uma.lab")).isInstanceOf(IllegalStateException.class);
        selfJwks.set(() -> JWKS);
        assertThat(resolver.apply("http://ps.uma.lab")).isEqualTo(JWKS);
        assertThat(resolver.apply("http://ps.uma.lab")).isEqualTo(JWKS);

        assertThat(resolver.apply(origin)).isNull();
        trust.add(new TrustedAgentServer(origin, "test", origin + "/jwks.json", "fp", "now"));
        assertThat(resolver.apply(origin)).isEqualTo(JWKS);
        assertThat(resolver.apply(origin)).isEqualTo(JWKS);

        trust.add(new TrustedAgentServer("http://127.0.0.1:1", "dead", "x", "fp", "now"));
        assertThat(resolver.apply("http://127.0.0.1:1")).isNull();
    }

    @Test
    void agentResolverWithoutSelfProviderReturnsNullForPs() {
        AgentServerJwksResolver resolver =
                new AgentServerJwksResolver("http://ps.uma.lab", new MemoryAgentServerTrustRegistry(null), null);
        assertThat(resolver.apply("http://ps.uma.lab")).isNull();
    }
}
