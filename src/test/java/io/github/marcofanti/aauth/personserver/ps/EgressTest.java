package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The outbound gate: HTTPS only, no internal addresses unless allow-listed, bounded bodies. */
class EgressTest {

    @AfterEach
    void resetAllowList() {
        Egress.allowHosts(null);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://127.0.0.1/x",
                "https://10.1.2.3/x",
                "https://172.16.0.1/x",
                "https://192.168.1.1/x",
                "https://169.254.169.254/latest/meta-data",
                "https://100.64.0.1/x",
                "https://0.0.0.0/x",
                "https://[::1]/x",
                "https://[fd00::1]/x",
                "https://[fe80::1]/x",
                "https://[::ffff:127.0.0.1]/x"
            })
    void internalAddressesAreRefused(String url) {
        assertThatThrownBy(() -> Egress.target(url))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("internal address");
    }

    @Test
    void onlyHttpsIsFetched() {
        assertThatThrownBy(() -> Egress.target("http://93.184.216.34/x"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("only https");
    }

    @Test
    void publicAddressesPass() {
        assertThat(Egress.target("https://93.184.216.34/.well-known/x"))
                .isEqualTo(URI.create("https://93.184.216.34/.well-known/x"));
    }

    @Test
    void allowListedHostsSkipTheAddressCheck() {
        Egress.allowHosts(" 127.0.0.1 , *.Uma.Lab");
        assertThat(Egress.target("https://127.0.0.1/x")).hasHost("127.0.0.1");
        assertThatThrownBy(() -> Egress.target("https://10.0.0.1/x")).hasMessageContaining("internal address");
    }

    @Test
    void wildcardPatternsMatchSubdomainsOnly() throws Exception {
        Egress.allowHosts("*.uma.lab");
        // uma.lab itself is not covered by *.uma.lab; it does not resolve publicly either.
        assertThatThrownBy(() -> Egress.target("https://uma.lab/x")).isInstanceOf(IllegalArgumentException.class);
        assertThat(Egress.isInternal(InetAddress.getByName("8.8.8.8"))).isFalse();
    }

    @Test
    void routedTestOriginsGoToTheirTarget() {
        HostRoutes.register("https://egress-route.example", "http://127.0.0.1:9");
        assertThat(Egress.target("https://egress-route.example/a?b=c"))
                .isEqualTo(URI.create("http://127.0.0.1:9/a?b=c"));
    }

    @Test
    void oversizedBodiesAreRefused() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] big = "x".repeat(Egress.MAX_BODY_BYTES + 1).getBytes(StandardCharsets.UTF_8);
        server.createContext("/big", exchange -> {
            exchange.sendResponseHeaders(200, big.length);
            exchange.getResponseBody().write(big);
            exchange.close();
        });
        server.start();
        try {
            String origin = "https://egress-big.example";
            HostRoutes.register(
                    origin, "http://127.0.0.1:" + server.getAddress().getPort());
            assertThatThrownBy(() -> SyncHttp.fetchJson(origin + "/big"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("exceeds");
        } finally {
            server.stop(0);
        }
    }
}
