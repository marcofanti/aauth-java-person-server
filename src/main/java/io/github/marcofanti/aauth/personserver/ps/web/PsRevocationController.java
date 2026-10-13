package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.IssuerUrls;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender;
import io.github.marcofanti.aauth.personserver.ps.RevocationService;
import io.github.marcofanti.aauth.personserver.ps.RevocationService.CallerKind;
import io.github.marcofanti.aauth.personserver.ps.ServerHttp;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.personserver.web.RequestExtract;
import io.github.marcofanti.aauth.personserver.web.SignatureError;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Draft-11 {@code revocation_endpoint} (§11.12, PS-110): callers sign as servers under the
 * {@code jwks_uri} scheme, and the verified identity is the issuer whose {@code jti} is revoked.
 * Agent providers (trusted, {@code dwk=aauth-agent.json}) revoke agent tokens; resources
 * ({@code dwk=aauth-resource.json}) revoke resource tokens.
 *
 * <p>The endpoint holds until the cascade is terminal, for at most {@link #MAX_HOLD} or the
 * caller's {@code Prefer: wait}, then answers 202 with a pending URL that the same identity polls
 * with a signed GET (§11.12.3 deferred completion).
 */
@Profile({"default", "portal", "ps"})
@RestController
public class PsRevocationController {

    private static final String SCHEME = "jwks_uri";
    private static final String AGENT_DWK = "aauth-agent.json";
    private static final String RESOURCE_DWK = "aauth-resource.json";

    private static final Duration MAX_HOLD = Duration.ofSeconds(20);
    private static final Pattern PREFER_WAIT = Pattern.compile("(?:^|[,;\\s])wait=(\\d+)");
    private static final String PENDING_PATH = "/revoke/pending/";
    private static final Logger log = LoggerFactory.getLogger(PsRevocationController.class);

    private record Caller(String iss, CallerKind kind) {}

    private final PendingRevocations pending = new PendingRevocations();
    private final PsContainer ps;
    private final String psOrigin;
    private final RevocationService service;

    public PsRevocationController(PsContainer ps, PsSettings settings) {
        this.ps = ps;
        this.psOrigin = IssuerUrls.normalizeIssuer(settings.origin());
        RevocationSender sender = new RevocationSender(ServerHttp.personServer(psOrigin, ps.psSigning()));
        this.service = new RevocationService(
                psOrigin,
                new RevocationService.Deps(
                        ps.revocations(),
                        ps.personTokenLedger(),
                        ps.issuedTokenStore(),
                        ps.pendingStore(),
                        (recipient, metadata, token) -> sender.send(recipient, metadata, token.jti(), token.exp())));
    }

    @PostMapping("/revoke")
    public ResponseEntity<Object> revoke(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        Caller caller = verifyCaller(signed);
        BodyCoverage.require(signed);
        Map<String, Object> body = parseBody(raw);
        String jti = body.get("jti") instanceof String value && !value.isBlank() ? value : null;
        Object rawExp = body.get("exp");
        Long exp = (rawExp instanceof Integer || rawExp instanceof Long) && ((Number) rawExp).longValue() > 0
                ? ((Number) rawExp).longValue()
                : null;
        if (jti == null || exp == null) {
            throw new ProblemError(400, "invalid_request", "jti (string) and exp (positive integer) are required");
        }
        CompletableFuture<?> cascade = service.start(caller.iss(), caller.kind(), jti, exp);
        if (awaitCascade(cascade, hold(request))) {
            return ResponseEntity.ok().build();
        }
        return deferred(pending.add(caller, cascade));
    }

    /** §11.12.3: the poller signs as the identity that made the revocation; anyone else gets 404. */
    @GetMapping(PENDING_PATH + "{id}")
    public ResponseEntity<Object> poll(HttpServletRequest request, @PathVariable("id") String id) {
        Caller caller = verifyCaller(RequestExtract.signedRequest(request, null));
        CompletableFuture<?> cascade = pending.find(id, caller);
        if (cascade == null) {
            return ResponseEntity.notFound().build();
        }
        if (!awaitCascade(cascade, hold(request))) {
            return deferred(id);
        }
        pending.remove(id);
        return ResponseEntity.ok().build();
    }

    private static Duration hold(HttpServletRequest request) {
        String prefer = request.getHeader("Prefer");
        Matcher wait = prefer == null ? null : PREFER_WAIT.matcher(prefer);
        if (wait == null || !wait.find()) {
            return MAX_HOLD;
        }
        try {
            Duration asked = Duration.ofSeconds(Long.parseLong(wait.group(1)));
            return asked.compareTo(MAX_HOLD) < 0 ? asked : MAX_HOLD;
        } catch (NumberFormatException e) {
            return MAX_HOLD;
        }
    }

    /** Whether the cascade finished within {@code hold}. */
    private static boolean awaitCascade(CompletableFuture<?> cascade, Duration hold) {
        try {
            cascade.get(hold.toMillis(), TimeUnit.MILLISECONDS);
            return true;
        } catch (TimeoutException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (ExecutionException e) {
            log.warn("revocation cascade failed", e.getCause());
            throw new ProblemError(500, "server_error", "the revocation cascade failed");
        }
    }

    private ResponseEntity<Object> deferred(String id) {
        return ResponseEntity.accepted()
                .header("Location", psOrigin + PENDING_PATH + id)
                .header("Retry-After", "0")
                .header("Cache-Control", "no-store")
                .body(Map.of("status", "pending"));
    }

    private Caller verifyCaller(SignedRequest signed) {
        if (!signed.hasSignatureHeaders()) {
            throw new SignatureError("invalid_signature", "Signature-Input, Signature and Signature-Key are required");
        }
        SignatureKeyHeader.Parsed key;
        try {
            key = SignatureKeyHeader.parse(signed.header("signature-key"));
        } catch (HttpSignatureException e) {
            throw new SignatureError("invalid_key", e.getMessage());
        }
        if (HttpSigAuth.createdAheadOfClock(signed)) {
            throw new SignatureError(SignatureError.CLOCK_SKEW, "signature created is ahead of the server clock");
        }
        if (!SCHEME.equals(key.scheme())) {
            throw new SignatureError("unsupported_scheme", "revocation callers sign as servers (jwks_uri)", SCHEME);
        }
        String id = key.params().get("id");
        String dwk = key.params().get("dwk");
        try {
            Identifiers.validateServerIdentifier(id);
        } catch (IllegalArgumentException e) {
            throw new SignatureError("invalid_key", "Signature-Key id is not a server identifier: " + e.getMessage());
        }
        String iss = IssuerUrls.normalizeIssuer(id);
        Caller caller = callerFor(iss, dwk);
        Map<String, Object> jwks = caller.kind() == CallerKind.AGENT_PROVIDER
                ? ps.agentJwksResolver().apply(iss)
                : ps.resourceJwksResolver().apply(iss);
        if (jwks == null) {
            throw new SignatureError("unknown_key", "no signing keys found for " + iss);
        }
        if (!signatureVerifies(signed, jwks)) {
            throw new SignatureError("invalid_signature", "HTTP signature verification failed");
        }
        return caller;
    }

    private Caller callerFor(String iss, String dwk) {
        if (AGENT_DWK.equals(dwk)) {
            if (!ps.agentJwksResolver().isTrusted(iss)) {
                throw new ProblemError(403, "unsupported_iss", "this PS does not trust agent provider " + iss);
            }
            return new Caller(iss, CallerKind.AGENT_PROVIDER);
        }
        if (RESOURCE_DWK.equals(dwk)) {
            // §11.12.3 MAY: only resources whose tokens this PS has verified; anyone else gets
            // unsupported_iss before the PS fetches anything on their say-so.
            if (!ps.revocations().isKnownResourceIssuer(iss)) {
                throw new ProblemError(403, "unsupported_iss", "this PS holds no resource tokens from " + iss);
            }
            return new Caller(iss, CallerKind.RESOURCE);
        }
        throw new ProblemError(403, "unsupported_iss", "revocations come from agent providers and resources");
    }

    private static boolean signatureVerifies(SignedRequest signed, Map<String, Object> jwks) {
        try {
            return SignatureVerifier.verify(VerifyRequest.builder(signed.method(), signed.targetUri())
                    .headers(signed.headers())
                    .body(signed.body())
                    .signatureHeaders(
                            signed.header("signature-input"),
                            signed.header("signature"),
                            signed.header("signature-key"))
                    .jwksFetcher((id, dwk, kid) -> jwks)
                    .build());
        } catch (HttpSignatureException e) {
            return false;
        }
    }

    private static Map<String, Object> parseBody(byte[] raw) {
        if (raw == null || raw.length == 0) {
            throw new ProblemError(400, "invalid_request", "a JSON body {jti, exp} is required");
        }
        try {
            return Json.readMap(new String(raw, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new ProblemError(400, "invalid_request", "the body is not a JSON object");
        }
    }
}
