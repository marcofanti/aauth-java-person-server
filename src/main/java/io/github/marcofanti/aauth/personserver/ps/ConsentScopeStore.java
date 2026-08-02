package io.github.marcofanti.aauth.personserver.ps;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.personserver.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Admin-configurable list of scopes that require user consent. */
public final class ConsentScopeStore {

    private static final Logger log = LoggerFactory.getLogger(ConsentScopeStore.class);
    private static final List<String> DEFAULT_SCOPES = List.of("require:user");

    private final Path filePath;
    private final Set<String> scopes = new HashSet<>();

    public ConsentScopeStore(String filePath) {
        this.filePath = (filePath == null || filePath.isEmpty()) ? null : Path.of(filePath);
        load();
    }

    private void load() {
        if (filePath == null) {
            scopes.addAll(DEFAULT_SCOPES);
            log.info("No consent scopes file configured; using defaults: {}", DEFAULT_SCOPES);
            return;
        }
        if (!Files.exists(filePath)) {
            scopes.addAll(DEFAULT_SCOPES);
            save();
            log.info("Created consent scopes file at {} with defaults", filePath);
            return;
        }
        try {
            Map<String, Object> data = Json.readMap(Files.readString(filePath, StandardCharsets.UTF_8));
            Object raw = data.get("scopes");
            if (!(raw instanceof List<?> list)) {
                throw new IllegalArgumentException("Invalid format: expected {\"scopes\": [...]}");
            }
            for (Object scope : list) {
                if (scope instanceof String s) {
                    scopes.add(s);
                }
            }
            log.info("Loaded {} consent scopes from {}", scopes.size(), filePath);
        } catch (IOException | IllegalArgumentException e) {
            log.warn("Failed to load consent scopes from {}: {}; using defaults", filePath, e.getMessage());
            scopes.clear();
            scopes.addAll(DEFAULT_SCOPES);
        }
    }

    private void save() {
        if (filePath == null) {
            return;
        }
        try {
            if (filePath.getParent() != null) {
                Files.createDirectories(filePath.getParent());
            }
            String payload = Json.MAPPER
                    .writerWithDefaultPrettyPrinter()
                    .writeValueAsString(Map.of("scopes", new TreeSet<>(scopes)));
            Files.writeString(filePath, payload, StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize consent scopes: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to save consent scopes to {}: {}", filePath, e.getMessage());
        }
    }

    public synchronized List<String> getScopes() {
        return new ArrayList<>(new TreeSet<>(scopes));
    }

    /** Add a scope; true if added, false if already present. */
    public synchronized boolean addScope(String scope) {
        String trimmed = scope.strip();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Scope cannot be empty");
        }
        if (scopes.contains(trimmed)) {
            return false;
        }
        scopes.add(trimmed);
        save();
        log.info("Added consent scope: {}", trimmed);
        return true;
    }

    /** Remove a scope; true if removed, false if not present. */
    public synchronized boolean removeScope(String scope) {
        if (!scopes.contains(scope)) {
            return false;
        }
        scopes.remove(scope);
        save();
        log.info("Removed consent scope: {}", scope);
        return true;
    }

    /** True if any of the requested (space-separated) scopes require user consent. */
    public synchronized boolean requiresConsent(String resourceScope) {
        if (resourceScope == null || resourceScope.isBlank()) {
            return false;
        }
        for (String requested : resourceScope.strip().split("\\s+")) {
            if (scopes.contains(requested)) {
                return true;
            }
        }
        return false;
    }
}
