package io.github.marcofanti.aauth.personserver;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.Map;

/** Shared Jackson mappers. {@link #CANONICAL} matches Python's canonical mission-blob JSON. */
public final class Json {

    public static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Sorted keys, compact separators, non-ASCII escaped — byte-for-byte equivalent to
     * Python's {@code json.dumps(obj, sort_keys=True, separators=(",", ":"))}.
     */
    public static final ObjectMapper CANONICAL = JsonMapper.builder()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(JsonWriteFeature.ESCAPE_NON_ASCII)
            .build();

    private Json() {}

    public static String write(Object value) {
        try {
            return MAPPER.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("failed to serialize " + value.getClass(), e);
        }
    }

    public static Map<String, Object> readMap(String json) {
        try {
            return MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("invalid JSON object", e);
        }
    }
}
