import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.JwksFetcher;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.RequestSigner;
import io.github.marcofanti.aauth.signing.SignRequest;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureScheme;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.PersonTokens;
import io.github.marcofanti.aauth.tokens.ResourceTokens;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
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
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A draft-11 AAuth walkthrough against the secure-mode portal (demo/run-secure-demo.sh). This
 * program plays two parties with the io.github.marcofanti:aauth library:
 *
 * <ul>
 *   <li>the agent, which registers at the Agent Server (as.uma.lab), proposes a mission at the
 *       Person Server (ps.uma.lab), and calls the resource;
 *   <li>a calendar resource at rs.uma.lab (served on 127.0.0.1:9997 behind Caddy), which accepts
 *       person and auth tokens, issues resource tokens, and receives revocations.
 * </ul>
 *
 * <p>You play the person in the portal; AUTO=1 makes the person's decisions over the API. Run it
 * through demo/secure-demo.sh, which builds the classpath.
 */
public final class Draft11Walkthrough {

    private static final String PS = env("PS", "https://ps.uma.lab");
    private static final String AS = env("AS", "https://as.uma.lab");
    private static final String RS = env("RS", "https://rs.uma.lab");
    private static final int RS_PORT = 9997;
    private static final String ADMIN_TOKEN = env("ADMIN_TOKEN", "demo-admin");
    private static final boolean AUTO = "1".equals(System.getenv("AUTO"));
    private static final String SCOPE = "calendar.read";
    private static final List<String> BODY_COMPONENTS = List.of("content-digest", "content-type");

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    // HTTP/1.1: Caddy forwards Host unchanged, so the signed @authority is the bare hostname.
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private static final BufferedReader STDIN = new BufferedReader(new InputStreamReader(System.in));

    private Draft11Walkthrough() {}

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value.replaceAll("/+$", "");
    }

    // ------------------------------------------------------------------ presentation

    private static void act(String title) {
        System.out.printf("%n\033[1;36m═══ %s\033[0m%n", title);
    }

    private static void note(String text) {
        System.out.println("  " + text);
    }

    private static void ok(String text) {
        System.out.println("  \033[32m✓\033[0m " + text);
    }

    private static IllegalStateException fail(String text) {
        return new IllegalStateException(text);
    }

    private static void pause() {
        if (AUTO) {
            return;
        }
        System.out.print("\n  ⏎ continue… ");
        try {
            STDIN.readLine();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void yourTurn(String instruction, String url) {
        if (AUTO) {
            note("(AUTO) " + instruction);
            return;
        }
        System.out.printf("%n  \033[1;33m▶ YOUR TURN:\033[0m %s%n    \033[4m%s\033[0m%n", instruction, url);
    }

    private static void show(Object value) {
        try {
            for (String line : JSON.writeValueAsString(value).split("\n")) {
                System.out.println("    " + line);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static Map<String, Object> claims(String jwt) {
        return Jwts.parse(jwt).payload();
    }

    // ------------------------------------------------------------------ HTTP

    /** An HTTP answer: status, headers (first values, lowercase names) and body. */
    private record Reply(int status, Map<String, String> headers, String body) {

        Map<String, Object> json() {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> map = body.isBlank() ? Map.of() : JSON.readValue(body, Map.class);
                return map;
            } catch (IOException e) {
                throw fail("expected JSON, got: " + body);
            }
        }

        String header(String name) {
            return headers.get(name.toLowerCase());
        }
    }

    /** A request signed with {@code key} under {@code scheme}; {@code scheme} null sends it unsigned. */
    private static Reply send(
            String method, String url, Object body, Map<String, String> extra, KeyPair key, SignatureScheme scheme) {
        byte[] bytes = null;
        Map<String, String> headers = new LinkedHashMap<>(extra);
        if (body != null) {
            try {
                bytes = JSON.writeValueAsBytes(body);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            headers.put("Content-Type", "application/json");
        }
        Map<String, String> all = new LinkedHashMap<>(headers);
        if (scheme != null) {
            SignRequest.Builder signing = SignRequest.builder(method, url)
                    .headers(headers)
                    .keyPair(key)
                    .scheme(scheme);
            if (bytes != null) {
                signing.body(bytes).additionalComponents(BODY_COMPONENTS);
            }
            all.putAll(RequestSigner.sign(signing.build()));
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .method(
                        method,
                        bytes == null
                                ? HttpRequest.BodyPublishers.noBody()
                                : HttpRequest.BodyPublishers.ofByteArray(bytes));
        all.forEach(request::header);
        try {
            HttpResponse<String> response = HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
            Map<String, String> replyHeaders = new LinkedHashMap<>();
            response.headers().map().forEach((name, values) -> replyHeaders.put(name.toLowerCase(), values.getFirst()));
            return new Reply(response.statusCode(), replyHeaders, response.body());
        } catch (IOException e) {
            throw fail(method + " " + url + " failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw fail("interrupted");
        }
    }

    private static Reply get(String url) {
        return send("GET", url, null, Map.of(), null, null);
    }

    private static Reply person(String method, String url, Object body) {
        return send(method, url, body, Map.of("Authorization", "Bearer " + ADMIN_TOKEN), null, null);
    }

    private static Reply expect(Reply reply, int status, String what) {
        if (reply.status() != status) {
            throw fail(what + " → HTTP " + reply.status() + " (expected " + status + "): " + reply.body());
        }
        return reply;
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw fail("interrupted");
        }
    }

    /**
     * Keys for a server identifier: its metadata document {@code dwk} names {@code jwks_uri}
     * (§11.4). Used by the resource to verify tokens and request signatures.
     */
    private static final JwksFetcher JWKS = (id, dwk, kid) -> {
        Reply metadata = get(id.replaceAll("/+$", "") + "/.well-known/" + (dwk == null ? "aauth-person.json" : dwk));
        if (metadata.status() != 200 || !(metadata.json().get("jwks_uri") instanceof String jwksUri)) {
            return null;
        }
        Reply jwks = get(jwksUri);
        return jwks.status() == 200 ? jwks.json() : null;
    };

    // ------------------------------------------------------------------ the resource

    /** The calendar resource at {@link #RS}: person token → resource token → auth token → data. */
    private static final class Resource {

        private final KeyPair key = KeyPairs.generateEd25519();
        private final Set<String> revoked = ConcurrentHashMap.newKeySet();
        private final HttpServer server;

        Resource() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", RS_PORT), 0);
            server.createContext("/.well-known/aauth-resource.json", exchange -> respond(exchange, 200, Map.of(), metadata()));
            server.createContext(
                    "/.well-known/jwks.json",
                    exchange -> respond(
                            exchange, 200, Map.of(), Map.of("keys", List.of(Jwk.publicKeyToJwk(key.getPublic(), "rs-kid")))));
            server.createContext("/calendar", this::calendar);
            server.createContext("/revoke", this::revoke);
            server.start();
        }

        void stop() {
            server.stop(0);
        }

        Set<String> revoked() {
            return revoked;
        }

        private static Map<String, Object> metadata() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("issuer", RS);
            out.put("jwks_uri", RS + "/.well-known/jwks.json");
            out.put("revocation_endpoint", RS + "/revoke");
            out.put("name", "Demo Calendar");
            out.put("description", "Reads your calendar events.");
            return out;
        }

        private static Map<String, String> headers(HttpExchange exchange) {
            Map<String, String> headers = new LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.getFirst()));
            return headers;
        }

        private static boolean signatureVerifies(String method, String target, Map<String, String> headers, byte[] body) {
            try {
                VerifyRequest.Builder request = VerifyRequest.builder(method, target)
                        .headers(headers)
                        .signatureHeaders(
                                headers.get("signature-input"), headers.get("signature"), headers.get("signature-key"))
                        .jwksFetcher(JWKS);
                if (body.length > 0) {
                    request.body(body);
                }
                return SignatureVerifier.verify(request.build());
            } catch (HttpSignatureException e) {
                return false;
            }
        }

        /** GET /calendar: the agent signs with the token it presents (scheme=jwt). */
        private void calendar(HttpExchange exchange) throws IOException {
            Map<String, String> headers = headers(exchange);
            byte[] body = exchange.getRequestBody().readAllBytes();
            String signatureKey = headers.get("signature-key");
            if (signatureKey == null || !signatureVerifies("GET", RS + exchange.getRequestURI(), headers, body)) {
                respond(exchange, 401, Map.of("AAuth-Requirement", AAuthHeaders.buildPersonTokenRequirement()), Map.of(
                        "error", "invalid_signature"));
                return;
            }
            String token = SignatureKeyHeader.parse(signatureKey).params().get("jwt");
            try {
                if (PersonTokens.TYPE.equals(Jwts.parse(token).header().get("typ"))) {
                    challenge(exchange, token);
                } else {
                    serve(exchange, token);
                }
            } catch (TokenException e) {
                respond(exchange, 401, Map.of(), Map.of("error", String.valueOf(e.errorCode()), "detail", e.getMessage()));
            }
        }

        /** §6.7.1: a verified person token earns a resource token naming it; the agent takes that to its PS. */
        private void challenge(HttpExchange exchange, String personToken) throws IOException {
            Map<String, Object> claims = PersonTokens.verify(
                    personToken, JWKS, TokenVerifier.Options.forType(PersonTokens.TYPE).withAudience(RS));
            if (revoked.contains(String.valueOf(claims.get("jti")))) {
                respond(exchange, 401, Map.of(), Map.of("error", "revoked_jwt"));
                return;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> cnf = (Map<String, Object>) ((Map<String, Object>) claims.get("cnf")).get("jwk");
            String resourceToken = ResourceTokens.create(ResourceTokens.Spec.builder(
                            RS, String.valueOf(claims.get("iss")), Jwk.thumbprint(cnf), key.getPrivate(), "rs-kid")
                    .presentedToken(personToken, JWKS)
                    .scope(SCOPE)
                    .build());
            respond(
                    exchange,
                    401,
                    Map.of("AAuth-Requirement", AAuthHeaders.buildAuthTokenRequirement(resourceToken)),
                    Map.of("error", "auth_token_required"));
        }

        private void serve(HttpExchange exchange, String authToken) throws IOException {
            Map<String, Object> claims =
                    TokenVerifier.verify(authToken, JWKS, TokenVerifier.Options.forType(AuthTokens.TYPE).withAudience(RS));
            if (revoked.contains(String.valueOf(claims.get("jti")))) {
                respond(exchange, 401, Map.of(), Map.of("error", "revoked_jwt"));
                return;
            }
            if (!List.of(String.valueOf(claims.get("scope")).split(" ")).contains(SCOPE)) {
                respond(exchange, 403, Map.of(), Map.of("error", "insufficient_scope"));
                return;
            }
            respond(exchange, 200, Map.of(), Map.of(
                    "person", claims.get("sub"),
                    "events", List.of(
                            Map.of("when", "Friday 19:00", "what", "Dinner at Lucia's"),
                            Map.of("when", "Saturday 10:00", "what", "Farmers market"))));
        }

        /** §11.12: the PS revokes the tokens it issued for this resource, signed as itself. */
        private void revoke(HttpExchange exchange) throws IOException {
            Map<String, String> headers = headers(exchange);
            byte[] body = exchange.getRequestBody().readAllBytes();
            String signatureKey = headers.get("signature-key");
            if (signatureKey == null || !signatureVerifies("POST", RS + "/revoke", headers, body)) {
                respond(exchange, 401, Map.of(), Map.of("error", "invalid_signature"));
                return;
            }
            String caller = SignatureKeyHeader.parse(signatureKey).params().get("id");
            if (!PS.equals(caller)) {
                respond(exchange, 403, Map.of(), Map.of("error", "unsupported_iss"));
                return;
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> request = JSON.readValue(body, Map.class);
            String jti = String.valueOf(request.get("jti"));
            revoked.add(jti);
            System.out.printf("    \033[35m[rs.uma.lab]\033[0m revocation from %s for jti %s%n", caller, jti);
            respond(exchange, 200, Map.of(), null);
        }

        private static void respond(HttpExchange exchange, int status, Map<String, String> headers, Object body)
                throws IOException {
            byte[] bytes = body == null ? new byte[0] : JSON.writeValueAsBytes(body);
            headers.forEach((name, value) -> exchange.getResponseHeaders().add(name, value));
            if (bytes.length > 0) {
                exchange.getResponseHeaders().add("Content-Type", "application/json");
            }
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) {
                exchange.getResponseBody().write(bytes);
            }
            exchange.close();
        }
    }

    // ------------------------------------------------------------------ the agent

    private static final KeyPair STABLE = KeyPairs.generateEd25519();
    private static final KeyPair EPHEMERAL = KeyPairs.generateEd25519();

    public static void main(String[] args) throws Exception {
        Resource resource = new Resource();
        try {
            run(resource);
        } catch (IllegalStateException e) {
            System.out.printf("  \033[31m✗ %s\033[0m%n", e.getMessage());
            System.exit(1);
        } finally {
            resource.stop();
        }
        System.exit(0);
    }

    private static void run(Resource resource) {
        discovery();
        String agentToken = register();
        String agentId = String.valueOf(claims(agentToken).get("sub"));
        String personToken = mission(agentToken);
        String resourceToken = challenge(personToken);
        String authToken = authToken(agentToken, resourceToken, personToken);
        callWithAuthToken(authToken);
        revoke(resource, agentId, agentToken, authToken);
        act("Finale");
        ok("Draft-11 end to end: registration, a mission with a person token, a resource");
        note("  challenge, an auth token from /auth-token, and a revocation that cascaded from");
        note("  the Agent Server through the Person Server to the resource.");
        System.out.println("\n\033[1m  fin.\033[0m");
    }

    private static void discovery() {
        act("Act 0 — Three parties, three HTTPS identifiers");
        Map<String, Object> ps = expect(get(PS + "/.well-known/aauth-person.json"), 200, "PS metadata").json();
        ok("Person Server " + PS + " — draft-11 endpoints:");
        for (String key : List.of("person_token_endpoint", "auth_token_endpoint", "mission_endpoint", "revocation_endpoint")) {
            note("    " + key + " = " + ps.get(key));
        }
        expect(get(AS + "/.well-known/aauth-agent.json"), 200, "Agent Server metadata");
        ok("Agent Server " + AS + " — issues this agent's identity.");
        expect(get(RS + "/.well-known/aauth-resource.json"), 200, "resource metadata (is rs.uma.lab routed?)");
        ok("Resource " + RS + " — served by this program, reached through Caddy.");
        note("Every identifier is a port-less HTTPS origin, as draft-11 requires.");
        yourTurn("Open the console and paste the token (" + ADMIN_TOKEN + ").", PS + "/ui/portal.html");
        pause();
    }

    private static String register() {
        act("Act 1 — Registration: an agent identity from the Agent Server");
        note("The agent makes a stable key and an ephemeral (per-device) key, and registers the");
        note("stable one in a request signed with the ephemeral key (Signature-Key scheme=hwk).");
        Map<String, Object> body = Map.of(
                "stable_pub", Jwk.publicKeyToJwk(STABLE.getPublic(), null), "agent_name", "Draft-11 walkthrough");
        Reply pending = expect(
                send("POST", AS + "/register", body, Map.of(), EPHEMERAL, new SignatureScheme.Hwk()), 202, "POST /register");
        String location = AS + pending.header("Location");
        String registrationId = location.substring(location.lastIndexOf('/') + 1);
        ok("202 — registration pending at " + location);
        yourTurn("Console → Registrations → Approve 'Draft-11 walkthrough'.", PS + "/ui/portal.html");
        if (AUTO) {
            expect(person("POST", AS + "/person/registrations/" + registrationId + "/approve", null), 200, "approve");
        }
        for (int attempt = 0; attempt < 150; attempt++) {
            Reply poll = send("GET", location, null, Map.of(), EPHEMERAL, new SignatureScheme.Hwk());
            if (poll.status() == 200) {
                String agentToken = String.valueOf(poll.json().get("agent_token"));
                ok("Approved. The agent token (aa-agent+jwt) the Agent Server minted:");
                show(claims(agentToken));
                note("cnf.jwk is the ephemeral key; ps names the Person Server this agent uses.");
                pause();
                return agentToken;
            }
            expect(poll, 202, "registration poll");
            sleep(Duration.ofSeconds(2));
        }
        throw fail("registration still pending after 5 minutes");
    }

    private static String mission(String agentToken) {
        act("Act 2 — Mission: purpose, tools and resources, approved by the Person Server");
        note("POST /agent-missions, signed with the agent token (scheme=jwt) and covering the body.");
        Map<String, Object> proposal = Map.of(
                "description", "Find a free evening this week for dinner with Alex",
                "tools", List.of(Map.of("name", "read_calendar", "description", "Read calendar events")),
                "resources", List.of(RS));
        Reply reply = send("POST", PS + "/agent-missions", proposal, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(agentToken));
        Map<String, Object> approval = deferredOrDone(reply, agentToken, "POST /agent-missions");
        ok("Mission approved; s256 = " + approval.get("s256"));
        @SuppressWarnings("unchecked")
        Map<String, String> personTokens = (Map<String, String>) approval.get("person_tokens");
        String personToken = personTokens == null ? null : personTokens.get(RS);
        if (personToken == null) {
            throw fail("the approval carries no person token for " + RS + ": " + approval);
        }
        ok("…and a person token (aa-person+jwt) for " + RS + ", bound to the mission:");
        show(claims(personToken));
        pause();
        return personToken;
    }

    private static String challenge(String personToken) {
        act("Act 3 — The resource asks for an auth token");
        note("The agent calls GET " + RS + "/calendar presenting its person token.");
        Reply reply = send("GET", RS + "/calendar", null, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(personToken));
        expect(reply, 401, "GET /calendar with a person token");
        String requirement = reply.header("AAuth-Requirement");
        ok("401 AAuth-Requirement: " + requirement.substring(0, Math.min(60, requirement.length())) + "…");
        String resourceToken = AAuthHeaders.parseAAuthHeader(requirement).resourceToken();
        note("The resource token (aa-resource+jwt) names the presented token and the agent key:");
        show(claims(resourceToken));
        pause();
        return resourceToken;
    }

    private static String authToken(String agentToken, String resourceToken, String personToken) {
        act("Act 4 — The Person Server issues the auth token");
        note("POST /auth-token with the resource token and the person token as presented_token.");
        Map<String, Object> body = Map.of(
                "resource_token", resourceToken,
                "presented_token", personToken,
                "justification", "Check the person's free evenings for the dinner mission");
        Reply reply = send("POST", PS + "/auth-token", body, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(agentToken));
        String authToken = String.valueOf(deferredOrDone(reply, agentToken, "POST /auth-token").get("auth_token"));
        ok("Auth token (aa-auth+jwt), bounded by the presented token's exp:");
        show(claims(authToken));
        pause();
        return authToken;
    }

    private static void callWithAuthToken(String authToken) {
        act("Act 5 — The resource serves the call");
        Reply reply = expect(
                send("GET", RS + "/calendar", null, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(authToken)),
                200,
                "GET /calendar with the auth token");
        ok("200 — the resource verified the auth token and the request signature:");
        show(reply.json());
        pause();
    }

    private static void revoke(Resource resource, String agentId, String agentToken, String authToken) {
        act("Act 6 — Revocation cascades: Agent Server → Person Server → resource");
        note("The person revokes the agent's binding at the Agent Server. The Agent Server revokes");
        note("the agent's live agent tokens at the PS, and the PS revokes every person token and");
        note("auth token it issued to that agent at the resources they were for.");
        yourTurn("Console → Bindings → Revoke the walkthrough agent.", PS + "/ui/portal.html");
        if (AUTO) {
            expect(person("POST", AS + "/person/bindings/" + agentId + "/revoke", null), 200, "revoke binding");
        }
        String authJti = String.valueOf(claims(authToken).get("jti"));
        for (int attempt = 0; attempt < 150 && !resource.revoked().contains(authJti); attempt++) {
            sleep(Duration.ofSeconds(2));
        }
        if (!resource.revoked().contains(authJti)) {
            throw fail("the resource never received the auth token's revocation");
        }
        ok("The resource received the PS's signed revocations (above).");
        Reply refused = send("GET", RS + "/calendar", null, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(authToken));
        expect(refused, 401, "GET /calendar with the revoked auth token");
        ok("The revoked auth token is refused: " + refused.json().get("error"));
        Reply ps = send(
                "POST",
                PS + "/agent-missions",
                Map.of("description", "One more try"),
                Map.of(),
                EPHEMERAL,
                new SignatureScheme.Jwt(agentToken));
        expect(ps, 401, "POST /agent-missions with the revoked agent token");
        ok("The PS refuses the revoked agent token: Signature-Error " + ps.header("Signature-Error"));
        pause();
    }

    /**
     * A 200 body, or — for a 202 — the person's decision followed by the pending URL's 200 body
     * (§11.8). The agent polls signed with its agent token.
     */
    private static Map<String, Object> deferredOrDone(Reply reply, String agentToken, String what) {
        if (reply.status() == 200) {
            return reply.json();
        }
        expect(reply, 202, what);
        Map<String, Object> deferred = reply.json();
        String code = String.valueOf(deferred.get("code"));
        ok("202 — the Person Server asks the person first (code " + code + ").");
        yourTurn("Approve the request on the consent page.", PS + "/ui/consent.html?code=" + code);
        if (AUTO) {
            String pendingId = String.valueOf(expect(get(PS + "/consent?code=" + code), 200, "GET /consent").json().get(
                    "pending_id"));
            expect(
                    send("POST", PS + "/consent/" + pendingId + "/decision", Map.of("approved", true), Map.of(), null, null),
                    200,
                    "consent decision");
        }
        String location = reply.header("Location");
        String pendingUrl = location.startsWith("/") ? PS + location : location;
        for (int attempt = 0; attempt < 150; attempt++) {
            sleep(Duration.ofSeconds(2));
            Reply poll = send("GET", pendingUrl, null, Map.of(), EPHEMERAL, new SignatureScheme.Jwt(agentToken));
            if (poll.status() == 200) {
                return poll.json();
            }
            expect(poll, 202, what + " (pending)");
        }
        throw fail(what + " still pending after 5 minutes");
    }
}
