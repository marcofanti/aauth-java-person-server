package io.github.marcofanti.aauth.personserver.ps;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** In-memory trust list with optional JSON persistence. */
public final class MemoryAgentServerTrustRegistry implements AgentServerTrustRegistry {

    private final Map<String, TrustedAgentServer> byIssuer = new LinkedHashMap<>();
    private final Path path;

    public MemoryAgentServerTrustRegistry(String persistencePath) {
        this.path = (persistencePath == null || persistencePath.isEmpty()) ? null : Path.of(persistencePath);
        if (path != null && Files.exists(path)) {
            load();
        }
    }

    private void load() {
        try {
            Map<String, Object> raw = Json.readMap(Files.readString(path, StandardCharsets.UTF_8));
            Object items = raw.getOrDefault("trusted", List.of());
            if (items instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> entry) {
                        TrustedAgentServer trusted = new TrustedAgentServer(
                                IssuerUrls.normalizeIssuer(String.valueOf(entry.get("issuer"))),
                                stringOr(entry.get("display_name"), ""),
                                String.valueOf(entry.get("jwks_uri")),
                                String.valueOf(entry.get("jwks_fingerprint")),
                                stringOr(entry.get("added_at"), ""));
                        byIssuer.put(trusted.issuer(), trusted);
                    }
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read trust file " + path, e);
        }
    }

    private static String stringOr(Object value, String fallback) {
        return value == null ? fallback : String.valueOf(value);
    }

    private void persist() {
        if (path == null) {
            return;
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        List<TrustedAgentServer> sorted = new ArrayList<>(byIssuer.values());
        sorted.sort(Comparator.comparing(TrustedAgentServer::issuer));
        for (TrustedAgentServer trusted : sorted) {
            Map<String, Object> row = new TreeMap<>();
            row.put("issuer", trusted.issuer());
            row.put("display_name", trusted.displayName());
            row.put("jwks_uri", trusted.jwksUri());
            row.put("jwks_fingerprint", trusted.jwksFingerprint());
            row.put("added_at", trusted.addedAt());
            rows.add(row);
        }
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            String payload = Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(Map.of("trusted", rows));
            Files.writeString(path, payload + "\n", StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize trust file", e);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to write trust file " + path, e);
        }
    }

    @Override
    public synchronized List<TrustedAgentServer> listTrusted() {
        List<TrustedAgentServer> out = new ArrayList<>(byIssuer.values());
        out.sort(Comparator.comparing(TrustedAgentServer::issuer));
        return out;
    }

    @Override
    public synchronized void add(TrustedAgentServer entry) {
        byIssuer.put(IssuerUrls.normalizeIssuer(entry.issuer()), entry);
        persist();
    }

    @Override
    public synchronized boolean remove(String issuer) {
        String key = IssuerUrls.normalizeIssuer(issuer);
        if (!byIssuer.containsKey(key)) {
            return false;
        }
        byIssuer.remove(key);
        persist();
        return true;
    }

    @Override
    public synchronized boolean isTrusted(String issuer) {
        return byIssuer.containsKey(IssuerUrls.normalizeIssuer(issuer));
    }
}
