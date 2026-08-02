package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.SignatureVerifier;
import io.github.marcofanti.aauth.signing.VerifyRequest;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Function;

/** Verify HTTP Message Signatures with {@code Signature-Key: sig=jwt} (aa-agent+jwt). */
public final class HttpSigAuth {

    /** Verified agent identity extracted from an {@code aa-agent+jwt}-signed request. */
    public record VerifiedAgent(
            String agentId, Map<String, Object> agentCnfJwk, String agentJkt, String agentIss, String agentTokenJwt) {}

    /** Raw signature header triple + request context needed for verification. */
    public record SignedRequest(String method, String targetUri, Map<String, String> headers, byte[] body) {

        public String header(String name) {
            return headers.get(name);
        }

        public boolean hasSignatureHeaders() {
            return header("signature-input") != null && header("signature") != null && header("signature-key") != null;
        }
    }

    private HttpSigAuth() {}

    static String extractJwtFromSignatureKey(SignatureKeyHeader.Parsed parsed) {
        String jwt = parsed.params().get("jwt");
        if (jwt == null || jwt.isEmpty()) {
            throw new IllegalArgumentException("No JWT value in jwt Signature-Key");
        }
        return jwt;
    }

    /** RFC 9421 verification for hwk (or any self-contained) scheme; false on bad signature. */
    public static boolean verifySignature(SignedRequest request) {
        try {
            return SignatureVerifier.verify(VerifyRequest.builder(request.method(), request.targetUri())
                    .headers(request.headers())
                    .body(request.body())
                    .signatureHeaders(
                            request.header("signature-input"),
                            request.header("signature"),
                            request.header("signature-key"))
                    .build());
        } catch (HttpSignatureException e) {
            return false;
        }
    }

    /** Compute the RFC 7638 thumbprint of the inline hwk public key. */
    public static String hwkThumbprint(SignatureKeyHeader.Parsed parsed) {
        Map<String, String> params = parsed.params();
        if (params.isEmpty()) {
            throw new IllegalArgumentException("Could not parse public key from Signature-Key");
        }
        Map<String, Object> jwk = new LinkedHashMap<>(params);
        return Jwk.thumbprint(jwk);
    }

    /**
     * Verify RFC 9421 signature and aa-agent+jwt in Signature-Key. Throws
     * {@link IllegalArgumentException} with a message mirroring the Python {@code ValueError}s.
     */
    public static VerifiedAgent verifyAgentJwtRequest(
            SignedRequest request, Function<String, Map<String, Object>> jwksFetcher, boolean insecureDev) {
        if (!request.hasSignatureHeaders()) {
            throw new IllegalArgumentException(
                    "Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)");
        }
        SignatureKeyHeader.Parsed parsed = SignatureKeyHeader.parse(request.header("signature-key"));
        if (!"jwt".equals(parsed.scheme())) {
            throw new IllegalArgumentException("Signature-Key must use scheme=jwt for this request");
        }
        String jwt = extractJwtFromSignatureKey(parsed);

        Map<String, Object> claims;
        try {
            claims = AgentTokens.verify(jwt, jwksFetcher, null);
        } catch (TokenException e) {
            String message = e.getMessage() == null ? "invalid agent token" : e.getMessage();
            if (message.contains("expired")) {
                throw new IllegalArgumentException("Agent token expired: " + message, e);
            }
            throw new IllegalArgumentException(message, e);
        }

        if (!insecureDev) {
            boolean ok;
            try {
                ok = SignatureVerifier.verify(VerifyRequest.builder(request.method(), request.targetUri())
                        .headers(request.headers())
                        .body(request.body())
                        .signatureHeaders(
                                request.header("signature-input"),
                                request.header("signature"),
                                request.header("signature-key"))
                        .jwksFetcher((id, dwk, kid) -> jwksFetcher.apply(id))
                        .build());
            } catch (HttpSignatureException e) {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            if (!ok) {
                throw new IllegalArgumentException("HTTP signature verification failed");
            }
        }

        String iss = String.valueOf(claims.getOrDefault("iss", ""));
        String sub = String.valueOf(claims.getOrDefault("sub", ""));
        Object cnf = claims.get("cnf");
        Object ephemeral = cnf instanceof Map<?, ?> cnfMap ? cnfMap.get("jwk") : null;
        if (!(ephemeral instanceof Map<?, ?> ephemeralMap)) {
            throw new IllegalArgumentException("Agent token missing cnf.jwk");
        }
        Map<String, Object> jwk = new LinkedHashMap<>();
        ephemeralMap.forEach((key, value) -> jwk.put(String.valueOf(key), value));
        return new VerifiedAgent(sub, jwk, Jwk.thumbprint(jwk), iss, jwt);
    }
}
