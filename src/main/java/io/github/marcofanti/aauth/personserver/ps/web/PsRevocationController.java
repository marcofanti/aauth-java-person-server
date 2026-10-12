package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.IssuerUrls;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.RevocationSender;
import io.github.marcofanti.aauth.personserver.ps.RevocationService;
import io.github.marcofanti.aauth.personserver.ps.RevocationService.CallerKind;
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
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Draft-11 {@code revocation_endpoint} (§11.12, PS-110): callers sign as servers under the
 * {@code jwks_uri} scheme, and the verified identity is the issuer whose {@code jti} is revoked.
 * Agent providers (trusted, {@code dwk=aauth-agent.json}) revoke agent tokens; resources
 * ({@code dwk=aauth-resource.json}) revoke resource tokens.
 */
@Profile({"default", "portal", "ps"})
@RestController
public class PsRevocationController {

    private static final String SCHEME = "jwks_uri";
    private static final String AGENT_DWK = "aauth-agent.json";
    private static final String RESOURCE_DWK = "aauth-resource.json";

    private record Caller(String iss, CallerKind kind) {}

    private final PsContainer ps;
    private final String psOrigin;
    private final RevocationService service;

    public PsRevocationController(PsContainer ps, PsSettings settings) {
        this.ps = ps;
        this.psOrigin = IssuerUrls.normalizeIssuer(settings.origin());
        RevocationSender sender = new RevocationSender(psOrigin, ps.psSigning());
        this.service = new RevocationService(
                psOrigin,
                new RevocationService.Deps(
                        ps.revocations(),
                        ps.personTokenLedger(),
                        ps.issuedTokenStore(),
                        ps.pendingStore(),
                        (recipient, token) -> sender.send(recipient, token.jti(), token.exp())));
    }

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
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
        service.revoke(caller.iss(), caller.kind(), jti, exp);
        return ResponseEntity.ok().build();
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
            Identifiers.validateServerUrl(id);
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
            if (!iss.equals(psOrigin) && !ps.trustRegistry().isTrusted(iss)) {
                throw new ProblemError(403, "unsupported_iss", "this PS does not trust agent provider " + iss);
            }
            return new Caller(iss, CallerKind.AGENT_PROVIDER);
        }
        if (RESOURCE_DWK.equals(dwk)) {
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
