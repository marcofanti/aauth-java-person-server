package io.github.marcofanti.aauth.personserver.ps.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.ps.AgentServerTrustRegistry;
import io.github.marcofanti.aauth.personserver.ps.IssuerUrls;
import io.github.marcofanti.aauth.personserver.ps.SyncHttp;
import io.github.marcofanti.aauth.personserver.ps.TrustedAgentServer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Trusted agent-server admin operations (probe metadata, fingerprint JWKS). */
public final class PsTrustOps {

    private PsTrustOps() {}

    static String jwksFingerprint(Map<String, Object> jwks) {
        try {
            String canonical = Json.CANONICAL.writeValueAsString(jwks);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (JsonProcessingException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("failed to fingerprint JWKS", e);
        }
    }

    public static List<Map<String, Object>> handleListTrusted(AgentServerTrustRegistry registry, String psOrigin) {
        String origin = IssuerUrls.normalizeIssuer(psOrigin);
        List<Map<String, Object>> rows = new ArrayList<>();
        Map<String, Object> self = new LinkedHashMap<>();
        self.put("issuer", origin);
        self.put("display_name", "This deployment (implicit trust when agent token iss matches)");
        self.put("jwks_uri", origin + "/.well-known/jwks.json");
        self.put("jwks_fingerprint", null);
        self.put("implicit", true);
        self.put("added_at", null);
        rows.add(self);
        for (TrustedAgentServer entry : registry.listTrusted()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("issuer", entry.issuer());
            row.put("display_name", entry.displayName());
            row.put("jwks_uri", entry.jwksUri());
            row.put("jwks_fingerprint", entry.jwksFingerprint());
            row.put("implicit", false);
            row.put("added_at", entry.addedAt());
            rows.add(row);
        }
        return rows;
    }

    /** Probe {@code aauth-agent.json} + JWKS, then register the issuer. */
    public static TrustedAgentServer handleAddTrusted(
            AgentServerTrustRegistry registry, String issuer, String displayName) {
        String iss = IssuerUrls.normalizeIssuer(issuer);
        String metaUrl = iss + "/.well-known/aauth-agent.json";
        Map<String, Object> meta = SyncHttp.fetchJson(metaUrl);
        Object jwksUri = meta.get("jwks_uri");
        if (!(jwksUri instanceof String uri) || uri.isEmpty()) {
            throw new IllegalArgumentException("No jwks_uri in metadata from " + metaUrl);
        }
        Map<String, Object> jwks = SyncHttp.fetchJson(uri);
        if (!(jwks.get("keys") instanceof List)) {
            throw new IllegalArgumentException("Invalid JWKS from " + uri);
        }
        String name = displayName == null || displayName.strip().isEmpty() ? iss : displayName.strip();
        String addedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        TrustedAgentServer entry = new TrustedAgentServer(iss, name, uri, jwksFingerprint(jwks), addedAt);
        registry.add(entry);
        return entry;
    }
}
