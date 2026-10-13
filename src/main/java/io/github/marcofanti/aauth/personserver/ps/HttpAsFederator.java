package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.ChallengeException;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AuthTokens;
import io.github.marcofanti.aauth.tokens.TokenVerifier;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Draft-11 four-party federation (§9.1): the PS calls the AS's {@code auth_token_endpoint} as a
 * server, follows the deferred loop, and verifies the auth token before delivering it (§9.1.3).
 * {@code requirement=claims} is answered inline; {@code interaction} and {@code clarification}
 * are passed down to the agent at once, and an approval or plain pending is waited on inline
 * until the deadline, then passed down too. Draft-10 requests keep the reference's fake
 * federator.
 */
public final class HttpAsFederator implements AsFederator {

    private static final Logger log = LoggerFactory.getLogger(HttpAsFederator.class);
    private static final String PERSON_TYPE = "aa-person+jwt";
    private static final Duration DEFAULT_DEADLINE = Duration.ofSeconds(20);
    private static final long MAX_POLL_WAIT_SECONDS = 5;

    private final AsFederator draft10;
    private final ServerHttp http;
    private final PersonTokenLedger personTokens;
    private final Duration deadline;

    public HttpAsFederator(AsFederator draft10, ServerHttp http, PersonTokenLedger personTokens) {
        this(draft10, http, personTokens, DEFAULT_DEADLINE);
    }

    /** {@code deadline} bounds the whole exchange with the AS, deferred responses included. */
    HttpAsFederator(AsFederator draft10, ServerHttp http, PersonTokenLedger personTokens, Duration deadline) {
        this.draft10 = draft10;
        this.http = http;
        this.personTokens = personTokens;
        this.deadline = deadline;
    }

    @Override
    public TokenOutcome requestAuthToken(String resourceToken, String agentToken, String upstreamToken) {
        return draft10.requestAuthToken(resourceToken, agentToken, upstreamToken);
    }

    @Override
    public TokenOutcome provideClaims(String pendingUrl, Map<String, Object> claims) {
        return draft10.provideClaims(pendingUrl, claims);
    }

    @Override
    public TokenOutcome pollAsPending(String pendingUrl) {
        return draft10.pollAsPending(pendingUrl);
    }

    /** The AS's endpoints, from its {@code aauth-access.json} metadata. */
    private record AccessServer(String issuer, String authTokenEndpoint, Map<String, Object> jwks) {}

    @Override
    public Federation federateDraft11(TokenRequest request, Map<String, Object> resourceClaims) {
        AccessServer as = discover(asIssuer(resourceClaims));
        // Recorded before sending: once the AS holds the token, revoking it must reach the AS
        // whatever this exchange returns (§11.12.4).
        recordPresentation(request, as.issuer());
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource_token", request.resourceToken());
        body.put("agent_token", request.draft11().agentToken());
        body.put("presented_token", request.draft11().presentedToken());
        if (request.upstreamToken() != null) {
            body.put("upstream_token", request.upstreamToken());
        }
        HttpResponse<String> response = call(() -> http.post(as.authTokenEndpoint(), body), as.issuer());
        return settle(new Exchange(as.issuer(), as, request, resourceClaims, true), as.authTokenEndpoint(), response);
    }

    @Override
    public Federation pollDraft11(TokenRequest request, Map<String, Object> resourceClaims, String asPendingUrl) {
        String issuer = asIssuer(resourceClaims);
        HttpResponse<String> response = call(() -> http.get(asPendingUrl), issuer);
        return settle(new Exchange(issuer, null, request, resourceClaims, false), asPendingUrl, response);
    }

    @Override
    public Federation clarifyDraft11(
            TokenRequest request, Map<String, Object> resourceClaims, String asPendingUrl, String answer) {
        String issuer = asIssuer(resourceClaims);
        HttpResponse<String> response =
                call(() -> http.post(asPendingUrl, Map.of("clarification_response", answer)), issuer);
        return settle(new Exchange(issuer, null, request, resourceClaims, false), asPendingUrl, response);
    }

    private static String asIssuer(Map<String, Object> resourceClaims) {
        return IssuerUrls.normalizeAudClaim(resourceClaims.get("aud"));
    }

    /**
     * One request's exchange with an AS. {@code as} is discovered lazily when only the issuer is
     * known; {@code waitInline} lets an approval or plain pending be polled until the deadline.
     */
    private record Exchange(
            String issuer,
            AccessServer as,
            TokenRequest request,
            Map<String, Object> resourceClaims,
            boolean waitInline) {}

    /** Follow the AS's answers from {@code url} to an auth token, a 202 to pass down, or an error. */
    private Federation settle(Exchange exchange, String url, HttpResponse<String> first) {
        Instant giveUpAt = Instant.now().plus(deadline);
        HttpResponse<String> response = first;
        String base = url;
        while (response.statusCode() == 202) {
            String pendingUrl = pendingUrl(base, response, exchange.issuer());
            AAuthHeaders.ParsedChallenge requirement = requirementOf(response, exchange.issuer());
            String level = requirement == null ? null : requirement.requirement();
            if ("claims".equals(level)) {
                if (Instant.now().isAfter(giveUpAt)) {
                    throw unreachable(
                            exchange.issuer(), "the AS did not finish within " + deadline.toSeconds() + " seconds");
                }
                HttpResponse<String> claimsAsked = response;
                response = call(() -> http.post(pendingUrl, claimsFor(claimsAsked)), exchange.issuer());
            } else if (exchange.waitInline() && waitable(level) && waitFits(response, giveUpAt)) {
                sleep(Math.min(Math.max(retryAfter(response), 1), MAX_POLL_WAIT_SECONDS), exchange.issuer());
                response = call(() -> http.get(pendingUrl), exchange.issuer());
            } else {
                return new Federation.Deferred(passDown(pendingUrl, requirement, response, exchange.issuer()));
            }
            base = pendingUrl;
        }
        if (response.statusCode() == 402) {
            // §9.1.2: the PS would settle payment per the AS's protocol; this PS has none.
            log.info(
                    "AS {} requires payment ({}); this PS does not settle payments",
                    exchange.issuer(),
                    response.headers().firstValue("WWW-Authenticate").orElse("no WWW-Authenticate"));
            throw unreachable(exchange.issuer(), "the AS requires payment, which this PS does not settle");
        }
        if (response.statusCode() != 200) {
            throw relayed(response, exchange.issuer());
        }
        String authToken = jsonOrEmpty(response.body()).get("auth_token") instanceof String token ? token : null;
        if (authToken == null) {
            throw unreachable(exchange.issuer(), "the AS answered 200 without an auth_token");
        }
        AccessServer as = exchange.as() != null ? exchange.as() : discover(exchange.issuer());
        long exp = verifyDelivery(authToken, as, exchange.request(), exchange.resourceClaims());
        return new Federation.Issued(new AuthTokenResponse(
                authToken, (int) Math.max(0, exp - Instant.now().getEpochSecond())));
    }

    /** Approval and plain pendings need nobody's action, so the PS may wait on them itself. */
    private static boolean waitable(String level) {
        return level == null || "approval".equals(level);
    }

    private static boolean waitFits(HttpResponse<String> response, Instant giveUpAt) {
        return !Instant.now().plusSeconds(retryAfter(response)).isAfter(giveUpAt);
    }

    private AccessServer discover(String asIssuer) {
        try {
            Map<String, Object> metadata = http.fetchJson(asIssuer + "/.well-known/aauth-access.json");
            if (!(metadata.get("auth_token_endpoint") instanceof String endpoint)
                    || !(metadata.get("jwks_uri") instanceof String jwksUri)) {
                throw unreachable(asIssuer, "AS metadata lacks auth_token_endpoint or jwks_uri");
            }
            return new AccessServer(asIssuer, endpoint, http.fetchJson(jwksUri));
        } catch (IllegalArgumentException e) {
            throw unreachable(asIssuer, "AS metadata unavailable: " + e.getMessage());
        }
    }

    /** The 202's pending URL, resolved against {@code base}; it must stay on that origin. */
    private static String pendingUrl(String base, HttpResponse<String> response, String issuer) {
        String location = response.headers().firstValue("Location").orElse(null);
        if (location == null) {
            throw unreachable(issuer, "the AS answered 202 without a Location");
        }
        URI pending = URI.create(base).resolve(location);
        if (!sameOrigin(pending, URI.create(base))) {
            throw unreachable(issuer, "the AS pending URL is not on the AS's origin");
        }
        return pending.toString();
    }

    private static AAuthHeaders.ParsedChallenge requirementOf(HttpResponse<String> response, String issuer) {
        String header = response.headers().firstValue("AAuth-Requirement").orElse(null);
        if (header == null) {
            return null;
        }
        try {
            return AAuthHeaders.parseAAuthHeader(header);
        } catch (ChallengeException e) {
            throw unreachable(issuer, "the AS sent a malformed AAuth-Requirement: " + e.getMessage());
        }
    }

    /** What the agent sees for an AS 202 (§9.1.2): interaction and clarification are its to meet. */
    private static AsPending passDown(
            String pendingUrl, AAuthHeaders.ParsedChallenge challenge, HttpResponse<String> response, String issuer) {
        Map<String, Object> body = jsonOrEmpty(response.body());
        boolean interacting = "interacting".equals(body.get("status"));
        String level = challenge == null ? null : challenge.requirement();
        if ("interaction".equals(level)) {
            String url = challenge.url();
            if (url == null || challenge.code() == null || !url.startsWith("https://")) {
                throw unreachable(issuer, "the AS interaction requirement lacks an https url or a code");
            }
            return new AsPending(
                    pendingUrl, RequirementLevel.INTERACTION, url, challenge.code(), null, null, null, interacting);
        }
        if ("clarification".equals(level)) {
            if (!(body.get("clarification") instanceof String question) || question.isBlank()) {
                throw unreachable(issuer, "the AS clarification has no question");
            }
            Integer timeout = body.get("timeout") instanceof Number seconds ? seconds.intValue() : null;
            return new AsPending(
                    pendingUrl,
                    RequirementLevel.CLARIFICATION,
                    null,
                    null,
                    question,
                    timeout,
                    strings(body.get("options")),
                    interacting);
        }
        return new AsPending(pendingUrl, RequirementLevel.APPROVAL, null, null, null, null, null, interacting);
    }

    private static Map<String, Object> jsonOrEmpty(String body) {
        if (body == null || body.isBlank()) {
            return Map.of();
        }
        try {
            return Json.readMap(body);
        } catch (RuntimeException e) {
            return Map.of();
        }
    }

    private static List<String> strings(Object value) {
        if (!(value instanceof List<?> items)) {
            return null;
        }
        List<String> out = new ArrayList<>();
        for (Object item : items) {
            out.add(String.valueOf(item));
        }
        return out;
    }

    /**
     * The PS holds no identity claims beyond the person's directed identifier, and {@code sub}
     * MUST NOT be sent (§9.2, PS-55), so every requested claim is answered as unavailable.
     */
    private static Map<String, Object> claimsFor(HttpResponse<String> response) {
        Object requested = Json.readMap(response.body()).get("required_claims");
        log.info("AS requested claims {}; this PS releases none", requested);
        return Map.of();
    }

    private static boolean sameOrigin(URI a, URI b) {
        return Objects.equals(a.getScheme(), b.getScheme())
                && Objects.equals(a.getHost(), b.getHost())
                && a.getPort() == b.getPort();
    }

    private static long retryAfter(HttpResponse<String> response) {
        String value = response.headers().firstValue("Retry-After").orElse(null);
        if (value == null) {
            return 1;
        }
        try {
            return Math.max(0, Long.parseLong(value.strip()));
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    private static void sleep(long seconds, String issuer) {
        try {
            Thread.sleep(Duration.ofSeconds(seconds));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unreachable(issuer, "interrupted while waiting for the AS");
        }
    }

    @FunctionalInterface
    private interface Call {
        HttpResponse<String> send() throws IOException, InterruptedException;
    }

    private static HttpResponse<String> call(Call call, String issuer) {
        try {
            return call.send();
        } catch (IOException | IllegalArgumentException e) {
            throw unreachable(issuer, "the AS is unreachable: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unreachable(issuer, "interrupted calling the AS");
        }
    }

    /** §9.1.3: relay a well-formed AS error with its status; anything else is {@code as_unreachable}. */
    private static ProblemError relayed(HttpResponse<String> response, String issuer) {
        Map<String, Object> body;
        try {
            body = Json.readMap(response.body());
        } catch (RuntimeException e) {
            return unreachable(issuer, "the AS answered " + response.statusCode() + " with a malformed body");
        }
        if (response.statusCode() < 400 || !(body.get("error") instanceof String error)) {
            return unreachable(issuer, "the AS answered " + response.statusCode() + " without an error");
        }
        Object detail = body.get("detail") != null ? body.get("detail") : body.get("error_description");
        return new ProblemError(response.statusCode(), error, detail == null ? null : String.valueOf(detail));
    }

    /** §9.1.3 steps 1–7; returns the auth token's {@code exp}. */
    private static long verifyDelivery(
            String authToken, AccessServer as, TokenRequest request, Map<String, Object> resourceClaims) {
        Map<String, Object> claims;
        try {
            claims = TokenVerifier.verify(
                    authToken,
                    (id, dwk, kid) -> as.issuer().equals(MissionUtils.stripTrailingSlash(id)) ? as.jwks() : null,
                    TokenVerifier.Options.forType(AuthTokens.TYPE)
                            .withIssuer(as.issuer())
                            .withAudience((String) resourceClaims.get("iss")));
        } catch (TokenException e) {
            throw unreachable(as, "the AS auth token does not verify: " + e.getMessage());
        }
        Object cnf = claims.get("cnf");
        Object jwk = cnf instanceof Map<?, ?> cnfMap ? cnfMap.get("jwk") : null;
        @SuppressWarnings("unchecked")
        String jkt = jwk instanceof Map<?, ?> key ? Jwk.thumbprint((Map<String, Object>) key) : null;
        if (!request.agentJkt().equals(jkt)) {
            throw unreachable(as, "the AS auth token is not bound to the agent's key");
        }
        if (!Objects.equals(resourceClaims.get("sub"), claims.get("sub"))) {
            throw unreachable(as, "the AS auth token sub is not this person's directed identifier");
        }
        if (!scopes(resourceClaims.get("scope")).containsAll(scopes(claims.get("scope")))) {
            throw unreachable(as, "the AS auth token scope is broader than the resource token's");
        }
        long exp = ((Number) claims.get("exp")).longValue();
        Long presentedExp = Jwts.parse(request.draft11().presentedToken()).numericClaim("exp");
        if (presentedExp == null || exp > presentedExp) {
            throw unreachable(as, "the AS auth token outlives the presented token");
        }
        return exp;
    }

    private static Set<String> scopes(Object scope) {
        return scope instanceof String value && !value.isBlank()
                ? Set.of(value.strip().split("\\s+"))
                : Set.of();
    }

    private void recordPresentation(TokenRequest request, String asIssuer) {
        Jwts.Decoded presented = Jwts.parse(request.draft11().presentedToken());
        if (PERSON_TYPE.equals(presented.header().get("typ")) && presented.claim("jti") != null) {
            personTokens.recordPresentation(presented.claim("jti"), asIssuer, request.agentJkt());
        }
    }

    private static ProblemError unreachable(AccessServer as, String detail) {
        return unreachable(as.issuer(), detail);
    }

    private static ProblemError unreachable(String asIssuer, String detail) {
        log.info("federation to {} failed: {}", asIssuer, detail);
        return new ProblemError(502, ProblemError.AS_UNREACHABLE, detail);
    }
}
