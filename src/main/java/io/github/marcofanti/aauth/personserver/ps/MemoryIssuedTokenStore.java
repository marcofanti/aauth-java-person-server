package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.Json;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link IssuedTokenStore} (dev / tests). */
public final class MemoryIssuedTokenStore implements IssuedTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<Map<String, Object>> records = new ArrayList<>();

    public static Map<String, Object> decodeJwtPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return Map.of();
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(padBase64(parts[1]));
            return Json.readMap(new String(decoded, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return Map.of();
        }
    }

    private static String padBase64(String value) {
        int remainder = value.length() % 4;
        return remainder == 0 ? value : value + "=".repeat(4 - remainder);
    }

    @Override
    public synchronized void recordIssued(IssuedToken issued) {
        Map<String, Object> payload = decodeJwtPayload(issued.authToken());
        Object jti = payload.get("jti");
        byte[] idBytes = new byte[16];
        RANDOM.nextBytes(idBytes);
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("issued_id", HexFormat.of().formatHex(idBytes));
        row.put("agent_id", issued.agentId());
        row.put("owner_id", issued.ownerId());
        row.put("resource_iss", issued.resourceIss());
        row.put("resource_scope", issued.resourceScope());
        row.put("justification", issued.justification());
        row.put("issue_method", issued.issueMethod());
        row.put("token_jti", jti);
        row.put("issued_at", Instant.now().toString());
        row.put("expires_at", issued.expiresAt() != null ? issued.expiresAt().toString() : null);
        records.add(row);
    }

    @Override
    public synchronized List<Map<String, Object>> listIssued() {
        List<Map<String, Object>> out = new ArrayList<>(records);
        Collections.reverse(out);
        return out;
    }
}
