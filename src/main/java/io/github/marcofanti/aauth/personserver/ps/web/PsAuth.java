package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.ErrorCodes;
import io.github.marcofanti.aauth.personserver.ps.AgentTokenRejectException;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.HttpError;
import io.github.marcofanti.aauth.personserver.web.SignatureError;
import io.github.marcofanti.aauth.personserver.web.UnsupportedSchemeError;
import io.github.marcofanti.aauth.signing.HttpSignatureException;
import io.github.marcofanti.aauth.signing.Jwts;
import io.github.marcofanti.aauth.signing.SignatureKeyHeader;
import java.util.Locale;
import java.util.Map;

/** Authentication: HWK / JWT HTTP message signatures + admin/user bearer tokens. */
public final class PsAuth {

    /** Context for {@code POST /token}: scheme=jwt when secure; HWK / stub headers in insecure dev. */
    public record TokenAgentContext(
            String agentId,
            String agentJkt,
            Map<String, Object> agentCnfJwk,
            boolean secureMode,
            String agentIss,
            Long agentTokenExp,
            String agentToken) {}

    private final PsSettings settings;
    private final PsContainer ps;
    private final String portalPersonToken;

    public PsAuth(PsSettings settings, PsContainer ps) {
        this(settings, ps, null);
    }

    /**
     * Portal mode: {@code portalPersonToken} (the AS person token) is also accepted on
     * admin routes, and user routes accept user/admin/person tokens (portal deps parity).
     */
    public PsAuth(PsSettings settings, PsContainer ps, String portalPersonToken) {
        this.settings = settings;
        this.ps = ps;
        this.portalPersonToken = portalPersonToken;
    }

    public String requireAgentId(SignedRequest request) {
        if (settings.insecureDev()) {
            String stubId = request.header("x-aauth-agent-id");
            if (stubId != null && !stubId.isEmpty()) {
                return stubId;
            }
            throw new HttpError(
                    401, "X-AAuth-Agent-Id required when AAUTH_PS_INSECURE_DEV enables stub agent identification");
        }

        if (!request.hasSignatureHeaders()) {
            throw new HttpError(401, "Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)");
        }

        SignatureKeyHeader.Parsed parsed = parseSignatureKey(request.header("signature-key"));
        String scheme = parsed.scheme();

        // Deferred polling (GET /pending/...) uses the same HTTPSig profile as POST /token:
        // aa-agent+jwt in Signature-Key (scheme=jwt), which requires JWKS resolution.
        if ("jwt".equals(scheme)) {
            try {
                return admit(HttpSigAuth.verifyAgentJwtRequest(request, ps.agentJwksResolver(), false))
                        .agentId();
            } catch (IllegalArgumentException e) {
                throw new HttpError(401, e.getMessage());
            }
        }

        // Draft-10 posture: reject unknown schemes before attempting verification, so the
        // response can advertise what this server accepts (Accept-Signature-* headers).
        if (!"hwk".equals(scheme)) {
            throw new UnsupportedSchemeError(
                    "Signature-Key must use scheme=hwk or scheme=jwt for this Person Server (got '" + scheme + "')");
        }
        if (!HttpSigAuth.verifySignature(request)) {
            throw new HttpError(401, "HTTP signature verification failed");
        }
        return hwkThumbprintOr401(parsed);
    }

    public TokenAgentContext requireTokenAgent(SignedRequest request) {
        if (settings.insecureDev()) {
            String stubId = request.header("x-aauth-agent-id");
            if (stubId != null && !stubId.isEmpty()) {
                return new TokenAgentContext(stubId, null, null, false, null, null, null);
            }
            if (request.hasSignatureHeaders()) {
                if (!HttpSigAuth.verifySignature(request)) {
                    throw new HttpError(401, "HTTP signature verification failed");
                }
                SignatureKeyHeader.Parsed parsed = parseSignatureKey(request.header("signature-key"));
                if (!"hwk".equals(parsed.scheme())) {
                    throw new HttpError(401, "Insecure dev token request: use scheme=hwk or X-AAuth-Agent-Id");
                }
                return new TokenAgentContext(hwkThumbprintOr401(parsed), null, null, false, null, null, null);
            }
            throw new HttpError(401, "Insecure dev: send X-AAuth-Agent-Id or an HWK-signed request for POST /token");
        }

        if (!request.hasSignatureHeaders()) {
            throw new AgentTokenRejectException(
                    "Missing HTTP signature headers (Signature-Input, Signature, Signature-Key)",
                    ErrorCodes.ERROR_INVALID_SIGNATURE);
        }
        SignatureKeyHeader.Parsed parsed;
        try {
            parsed = SignatureKeyHeader.parse(request.header("signature-key"));
        } catch (HttpSignatureException e) {
            throw new AgentTokenRejectException(e.getMessage(), ErrorCodes.ERROR_INVALID_SIGNATURE);
        }
        if (!"jwt".equals(parsed.scheme())) {
            throw new AgentTokenRejectException(
                    "POST /token requires Signature-Key scheme=jwt when AAUTH_PS_INSECURE_DEV is false",
                    ErrorCodes.ERROR_INVALID_SIGNATURE);
        }
        if (HttpSigAuth.createdAheadOfClock(request)) {
            throw new AgentTokenRejectException(
                    "signature created is ahead of the server clock", SignatureError.CLOCK_SKEW);
        }

        HttpSigAuth.VerifiedAgent verified;
        try {
            verified = HttpSigAuth.verifyAgentJwtRequest(request, ps.agentJwksResolver(), false);
        } catch (IllegalArgumentException e) {
            String message = e.getMessage() == null ? "invalid agent token" : e.getMessage();
            String lower = message.toLowerCase(Locale.ROOT);
            if (lower.contains("agent token expired") || lower.contains("expiredsignature")) {
                throw new AgentTokenRejectException(message, AgentTokenRejectException.EXPIRED_AGENT_TOKEN);
            }
            if (lower.contains("http signature verification failed")
                    || lower.contains("missing http signature")
                    || lower.contains("signature-key must use scheme=jwt")) {
                throw new AgentTokenRejectException(message, ErrorCodes.ERROR_INVALID_SIGNATURE);
            }
            throw new AgentTokenRejectException(message, AgentTokenRejectException.INVALID_AGENT_TOKEN);
        }
        admit(verified);
        Long agentTokenExp = Jwts.parse(verified.agentTokenJwt()).numericClaim("exp");
        return new TokenAgentContext(
                verified.agentId(),
                verified.agentJkt(),
                verified.agentCnfJwk(),
                true,
                verified.agentIss(),
                agentTokenExp,
                verified.agentTokenJwt());
    }

    /**
     * Refuse an agent token its provider revoked (§11.12.5), and otherwise remember its
     * {@code (iss, jti)} and {@code sub} so a later revocation can cascade (§11.12.4 Records).
     */
    private HttpSigAuth.VerifiedAgent admit(HttpSigAuth.VerifiedAgent verified) {
        Jwts.Decoded token = Jwts.parse(verified.agentTokenJwt());
        String jti = token.claim("jti");
        Long exp = token.numericClaim("exp");
        if (jti == null || exp == null) {
            return verified;
        }
        if (ps.revocations().isRevoked(verified.agentIss(), jti)) {
            throw new SignatureError("revoked_jwt", "the agent provider has revoked this agent token");
        }
        ps.revocations().recordAgentToken(verified.agentIss(), jti, verified.agentId(), exp);
        return verified;
    }

    private static SignatureKeyHeader.Parsed parseSignatureKey(String headerValue) {
        try {
            return SignatureKeyHeader.parse(headerValue);
        } catch (HttpSignatureException e) {
            throw new HttpError(401, e.getMessage());
        }
    }

    private static String hwkThumbprintOr401(SignatureKeyHeader.Parsed parsed) {
        try {
            return HttpSigAuth.hwkThumbprint(parsed);
        } catch (IllegalArgumentException e) {
            throw new HttpError(401, "Could not parse public key from Signature-Key");
        }
    }

    public void requireAdmin(String authorization) {
        String expected = settings.adminToken();
        if (expected == null) {
            return;
        }
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new HttpError(401, "Authorization: Bearer required");
        }
        String got = authorization.substring("Bearer ".length()).strip();
        if (got.equals(expected)) {
            return;
        }
        if (portalPersonToken != null && got.equals(portalPersonToken)) {
            return;
        }
        throw new HttpError(403, "Invalid admin token");
    }

    public String requireUser(String authorization) {
        if (portalPersonToken != null) {
            // Portal: accepts PS user token, PS admin token, or AS person token.
            if (authorization == null || !authorization.startsWith("Bearer ")) {
                throw new HttpError(401, "Authorization: Bearer required");
            }
            String got = authorization.substring("Bearer ".length()).strip();
            if (got.equals(portalPersonToken)
                    || (settings.userToken() != null && got.equals(settings.userToken()))
                    || (settings.adminToken() != null && got.equals(settings.adminToken()))) {
                return settings.userId();
            }
            throw new HttpError(403, "Invalid user token");
        }
        String expected = settings.userToken();
        if (expected == null) {
            throw new HttpError(503, "Legal user API not configured (set AAUTH_PS_USER_TOKEN)");
        }
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new HttpError(401, "Authorization: Bearer required");
        }
        String got = authorization.substring("Bearer ".length()).strip();
        if (!got.equals(expected)) {
            throw new HttpError(403, "Invalid user token");
        }
        return settings.userId();
    }
}
