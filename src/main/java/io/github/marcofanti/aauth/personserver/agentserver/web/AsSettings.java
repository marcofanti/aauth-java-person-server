package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.model.AgentServerMetadata;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Agent Server configuration from the same {@code AAUTH_AS_*} env vars as the Python server. */
public record AsSettings(
        String issuer,
        String serverDomain,
        String publicOrigin,
        String signingKeyPath,
        String previousKeyPath,
        int agentTokenLifetime,
        int registrationTtl,
        int signatureWindow,
        String clientName,
        String personToken,
        String databaseUrl,
        boolean insecureDev) {

    private static final Logger log = LoggerFactory.getLogger(AsSettings.class);

    public static AsSettings fromEnv(Map<String, String> env) {
        AsSettings settings = new AsSettings(
                env.getOrDefault("AAUTH_AS_ISSUER", "https://agent-server.example"),
                env.getOrDefault("AAUTH_AS_SERVER_DOMAIN", "agent-server.example"),
                env.getOrDefault("AAUTH_AS_PUBLIC_ORIGIN", "http://localhost:8800"),
                emptyToNull(env.get("AAUTH_AS_SIGNING_KEY_PATH")),
                emptyToNull(env.get("AAUTH_AS_PREVIOUS_KEY_PATH")),
                Integer.parseInt(env.getOrDefault("AAUTH_AS_AGENT_TOKEN_LIFETIME", "86400")),
                Integer.parseInt(env.getOrDefault("AAUTH_AS_REGISTRATION_TTL", "3600")),
                Integer.parseInt(env.getOrDefault("AAUTH_AS_SIGNATURE_WINDOW", "60")),
                env.getOrDefault("AAUTH_AS_CLIENT_NAME", "AAuth Agent Server"),
                env.getOrDefault("AAUTH_AS_PERSON_TOKEN", "changeme"),
                emptyToNull(env.getOrDefault("AAUTH_AS_DATABASE_URL", env.getOrDefault("AAUTH_DATABASE_URL", ""))),
                parseBool(env.getOrDefault("AAUTH_AS_INSECURE_DEV", "false")));
        if ("changeme".equals(settings.personToken()) && !settings.insecureDev()) {
            log.warn("AAUTH_AS_PERSON_TOKEN is set to the default value 'changeme'. "
                    + "Change it before exposing this server.");
        }
        if (!settings.insecureDev() && settings.publicOrigin().startsWith("http://")) {
            log.warn("AAUTH_AS_PUBLIC_ORIGIN uses http:// while INSECURE_DEV=false; "
                    + "spec requires HTTPS in production.");
        }
        return settings;
    }

    private static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }

    private static boolean parseBool(String value) {
        return switch (value.strip().toLowerCase(java.util.Locale.ROOT)) {
            case "true", "1", "yes", "on" -> true;
            default -> false;
        };
    }

    public String origin() {
        String out = publicOrigin;
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }

    public AgentServerMetadata metadata() {
        String o = origin();
        return new AgentServerMetadata(
                issuer, o + "/.well-known/jwks.json", clientName, o + "/register", o + "/refresh");
    }

    /** Copy with portal-aligned issuer, origin, and client name (phase 6). */
    public AsSettings withPortalAlignment(String portalOrigin, String portalClientName) {
        return new AsSettings(
                portalOrigin,
                serverDomain,
                portalOrigin,
                signingKeyPath,
                previousKeyPath,
                agentTokenLifetime,
                registrationTtl,
                signatureWindow,
                portalClientName,
                personToken,
                databaseUrl,
                insecureDev);
    }
}
