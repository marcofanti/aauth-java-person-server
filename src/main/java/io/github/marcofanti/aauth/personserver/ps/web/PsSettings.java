package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.PSMetadata;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Person Server configuration, read from the same {@code AAUTH_PS_*} environment variables
 * as the Python server (exact names — Spring relaxed binding is deliberately not used).
 */
public record PsSettings(
        String publicOrigin,
        boolean insecureDev,
        String adminToken,
        String userToken,
        String userId,
        boolean autoApproveToken,
        boolean autoApproveMission,
        String jwksUri,
        String agentJwtStub,
        int pendingTtlSeconds,
        String signingKeyPath,
        String trustFile,
        int authTokenLifetime,
        String databaseUrl,
        String consentScopesFile,
        String missionEvaluator) {

    private static final Logger log = LoggerFactory.getLogger(PsSettings.class);

    public static PsSettings fromEnv(Map<String, String> env) {
        PsSettings settings = new PsSettings(
                env.getOrDefault("AAUTH_PS_PUBLIC_ORIGIN", "http://localhost:8765"),
                parseBool(env.getOrDefault("AAUTH_PS_INSECURE_DEV", "true")),
                emptyToNull(env.get("AAUTH_PS_ADMIN_TOKEN")),
                emptyToNull(env.get("AAUTH_PS_USER_TOKEN")),
                env.getOrDefault("AAUTH_PS_USER_ID", "user"),
                parseBool(env.getOrDefault("AAUTH_PS_AUTO_APPROVE_TOKEN", "false")),
                parseBool(env.getOrDefault("AAUTH_PS_AUTO_APPROVE_MISSION", "true")),
                emptyToNull(env.get("AAUTH_PS_JWKS_URI")),
                env.getOrDefault("AAUTH_PS_AGENT_JWT_STUB", "stub-agent-jwt"),
                Integer.parseInt(env.getOrDefault("AAUTH_PS_PENDING_TTL_SECONDS", "600")),
                nullableWithDefault(env.get("AAUTH_PS_SIGNING_KEY_PATH"), ".aauth/ps-signing-key.pem"),
                nullableWithDefault(env.get("AAUTH_PS_TRUST_FILE"), ".aauth/ps-trusted-agents.json"),
                Integer.parseInt(env.getOrDefault("AAUTH_PS_AUTH_TOKEN_LIFETIME", "3600")),
                emptyToNull(env.getOrDefault("AAUTH_PS_DATABASE_URL", env.getOrDefault("AAUTH_DATABASE_URL", ""))),
                nullableWithDefault(env.get("AAUTH_PS_CONSENT_SCOPES_FILE"), ".aauth/consent-scopes.json"),
                emptyToNull(env.get("AAUTH_PS_MISSION_EVALUATOR")));
        if (!settings.insecureDev() && settings.publicOrigin().startsWith("http://")) {
            log.warn("AAUTH_PS_PUBLIC_ORIGIN uses http:// while INSECURE_DEV=false; "
                    + "spec requires interaction URLs to use https in production.");
        }
        return settings;
    }

    static boolean parseBool(String value) {
        return switch (value.strip().toLowerCase(java.util.Locale.ROOT)) {
            case "true", "1", "yes", "on" -> true;
            default -> false;
        };
    }

    static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }

    /** Unset → default; explicitly empty → null (Python's empty-string-means-disabled). */
    static String nullableWithDefault(String value, String defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        return value.isEmpty() ? null : value;
    }

    public String origin() {
        String out = publicOrigin;
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    public PSMetadata metadata() {
        String o = origin();
        String jwks = jwksUri != null ? jwksUri : o + "/.well-known/jwks.json";
        return new PSMetadata(
                o,
                o + "/token",
                o + "/mission",
                o + "/permission",
                o + "/audit",
                o + "/interaction",
                o + "/missions",
                jwks);
    }
}
