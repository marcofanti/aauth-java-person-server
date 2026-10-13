package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Draft-11 four-party federation (§9.1): the PS calls the AS's {@code auth_token_endpoint} as a
 * server, follows the deferred loop, and verifies the auth token before delivering it (§9.1.3).
 * Draft-10 requests keep the reference's fake federator.
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
    public AuthTokenResponse federateDraft11(TokenRequest request, Map<String, Object> resourceClaims) {
        AccessServer as = discover(IssuerUrls.normalizeAudClaim(resourceClaims.get("aud")));
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
        Instant giveUpAt = Instant.now().plus(deadline);
        HttpResponse<String> response = call(() -> http.post(as.authTokenEndpoint(), body), as);
        while (response.statusCode() == 202) {
            response = followDeferred(response, as, giveUpAt);
        }
        if (response.statusCode() != 200) {
            throw relayed(response, as);
        }
        String authToken = Json.readMap(response.body()).get("auth_token") instanceof String token ? token : null;
        if (authToken == null) {
            throw unreachable(as, "the AS answered 200 without an auth_token");
        }
        long exp = verifyDelivery(authToken, as, request, resourceClaims);
        return new AuthTokenResponse(
                authToken, (int) Math.max(0, exp - Instant.now().getEpochSecond()));
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

    /** §9.1.2 / §9.2: answer {@code requirement=claims}, otherwise poll the pending URL. */
    private HttpResponse<String> followDeferred(HttpResponse<String> response, AccessServer as, Instant giveUpAt) {
        String location = response.headers().firstValue("Location").orElse(null);
        if (location == null) {
            throw unreachable(as, "the AS answered 202 without a Location");
        }
        URI pending = URI.create(as.authTokenEndpoint()).resolve(location);
        if (!sameOrigin(pending, URI.create(as.authTokenEndpoint()))) {
            throw unreachable(as, "the AS pending URL is not on the AS's origin");
        }
        if (Instant.now().isAfter(giveUpAt)) {
            throw unreachable(as, "the AS did not finish within " + deadline.toSeconds() + " seconds");
        }
        String pendingUrl = pending.toString();
        String requirement = response.headers().firstValue("AAuth-Requirement").orElse("");
        if (requirement.contains("requirement=claims")) {
            return call(() -> http.post(pendingUrl, claimsFor(response)), as);
        }
        long wait = response.headers()
                .firstValue("Retry-After")
                .map(HttpAsFederator::seconds)
                .orElse(1L);
        if (Instant.now().plusSeconds(wait).isAfter(giveUpAt)) {
            throw unreachable(as, "the AS did not finish within " + deadline.toSeconds() + " seconds");
        }
        sleep(Math.min(Math.max(wait, 1), MAX_POLL_WAIT_SECONDS));
        return call(() -> http.get(pendingUrl), as);
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

    private static long seconds(String retryAfter) {
        try {
            return Long.parseLong(retryAfter.strip());
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    private static void sleep(long seconds) {
        try {
            Thread.sleep(Duration.ofSeconds(seconds));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ProblemError(502, "as_unreachable", "interrupted while waiting for the AS");
        }
    }

    @FunctionalInterface
    private interface Exchange {
        HttpResponse<String> send() throws IOException, InterruptedException;
    }

    private static HttpResponse<String> call(Exchange exchange, AccessServer as) {
        try {
            return exchange.send();
        } catch (IOException | IllegalArgumentException e) {
            throw unreachable(as, "the AS is unreachable: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unreachable(as, "interrupted calling the AS");
        }
    }

    /** §9.1.3: relay a well-formed AS error with its status; anything else is {@code as_unreachable}. */
    private static ProblemError relayed(HttpResponse<String> response, AccessServer as) {
        Map<String, Object> body;
        try {
            body = Json.readMap(response.body());
        } catch (RuntimeException e) {
            return unreachable(as, "the AS answered " + response.statusCode() + " with a malformed body");
        }
        if (response.statusCode() < 400 || !(body.get("error") instanceof String error)) {
            return unreachable(as, "the AS answered " + response.statusCode() + " without an error");
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
