package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.VerifiedRequest;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import io.github.marcofanti.aauth.signing.keys.Jwk;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * HTTP Message Signature verification (RFC 9421) for Agent Server routes. Wraps the library
 * verifier and adds best-effort replay protection plus hwk / jkt-jwt result extraction.
 */
public final class HttpSigVerifier {

    private final ReplayCache replay;
    private final boolean insecureDev;

    public HttpSigVerifier(ReplayCache replay, boolean insecureDev) {
        this.replay = replay;
        this.insecureDev = insecureDev;
    }

    public VerifiedRequest verify(SignedRequest request) {
        if (!request.hasSignatureHeaders()) {
            throw new InvalidSignatureException(
                    "Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)");
        }

        if (!insecureDev && !HttpSigAuth.verifySignature(request)) {
            throw new InvalidSignatureException("HTTP signature verification failed");
        }

        SignatureKeyHeader.Parsed parsed;
        try {
            parsed = SignatureKeyHeader.parse(request.header("signature-key"));
        } catch (HttpSignatureException e) {
            throw new InvalidSignatureException(e.getMessage());
        }
        return switch (parsed.scheme()) {
            case "hwk" -> extractHwk(parsed);
            case "jkt-jwt" -> extractJktJwt(parsed);
            default ->
                throw new InvalidSignatureException("Unsupported Signature-Key scheme: '" + parsed.scheme() + "'");
        };
    }

    private VerifiedRequest extractHwk(SignatureKeyHeader.Parsed parsed) {
        Map<String, String> params = parsed.params();
        if (params.isEmpty()) {
            throw new InvalidSignatureException("Could not parse public key from hwk Signature-Key");
        }
        Map<String, Object> jwk = new LinkedHashMap<>(params);
        checkReplay(computeThumbprint(jwk));
        return new VerifiedRequest("hwk", jwk);
    }

    private VerifiedRequest extractJktJwt(SignatureKeyHeader.Parsed parsed) {
        String jwt = parsed.params().get("jwt");
        if (jwt == null || jwt.isEmpty()) {
            throw new InvalidSignatureException("No JWT value in jkt-jwt Signature-Key");
        }

        Map<String, Object> payload = decodeJwtPayload(jwt);

        Object issClaim = payload.get("iss");
        String stableJkt = issClaim == null ? "" : String.valueOf(issClaim);
        if (!stableJkt.startsWith("urn:jkt:")) {
            throw new InvalidSignatureException("jkt-jwt iss is not a JKT: '" + stableJkt + "'");
        }

        Object cnf = payload.get("cnf");
        Object ephemeral = cnf instanceof Map<?, ?> cnfMap ? cnfMap.get("jwk") : null;
        if (!(ephemeral instanceof Map<?, ?> ephemeralMap)) {
            throw new InvalidSignatureException("No cnf.jwk in jkt-jwt payload");
        }
        Map<String, Object> ephemeralPub = new LinkedHashMap<>();
        ephemeralMap.forEach((key, value) -> ephemeralPub.put(String.valueOf(key), value));

        checkReplay(computeThumbprint(ephemeralPub));
        return new VerifiedRequest("jkt-jwt", ephemeralPub, stableJkt);
    }

    /** Decode a JWT payload without verifying (signature already checked via RFC 9421). */
    static Map<String, Object> decodeJwtPayload(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new InvalidSignatureException("Could not decode jkt-jwt JWT: not a compact JWT");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64(parts[1]));
            return Json.readMap(new String(decoded, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            throw new InvalidSignatureException("Could not decode jkt-jwt JWT: " + e.getMessage());
        }
    }

    private static String padBase64(String value) {
        int remainder = value.length() % 4;
        return remainder == 0 ? value : value + "=".repeat(4 - remainder);
    }

    private void checkReplay(String thumbprint) {
        // ReplayCache is best-effort: the library already enforces the 60 s window; a
        // duplicate here was already rejected upstream, so never double-error (Python parity).
        try {
            replay.checkAndRecord(thumbprint, 0);
        } catch (ReplayException e) {
            // Intentionally swallowed — see above.
        }
    }

    private static String computeThumbprint(Map<String, Object> jwk) {
        try {
            return Jwk.thumbprint(jwk);
        } catch (RuntimeException e) {
            return String.valueOf(jwk);
        }
    }
}
