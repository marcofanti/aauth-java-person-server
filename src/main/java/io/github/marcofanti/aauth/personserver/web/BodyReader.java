package io.github.marcofanti.aauth.personserver.web;

import io.github.marcofanti.aauth.personserver.Json;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/** Typed access to a JSON request body with FastAPI-shaped validation errors. */
public final class BodyReader {

    private final Map<String, Object> data;

    private BodyReader(Map<String, Object> data) {
        this.data = data;
    }

    public static BodyReader parse(byte[] body) {
        if (body == null || body.length == 0) {
            throw new BodyValidationException("request body required");
        }
        try {
            return new BodyReader(Json.readMap(new String(body, StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException e) {
            throw new BodyValidationException("invalid JSON body: " + e.getMessage());
        }
    }

    public String requireString(String field) {
        Object value = data.get(field);
        if (!(value instanceof String text) || text.isEmpty() && !data.containsKey(field)) {
            throw new BodyValidationException("field '" + field + "' required");
        }
        return (String) value;
    }

    public String optString(String field) {
        Object value = data.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String)) {
            throw new BodyValidationException("field '" + field + "' must be a string");
        }
        return (String) value;
    }

    public Boolean requireBoolean(String field) {
        Object value = data.get(field);
        if (!(value instanceof Boolean bool)) {
            throw new BodyValidationException("field '" + field + "' required (boolean)");
        }
        return bool;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> optMap(String field) {
        Object value = data.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Map)) {
            throw new BodyValidationException("field '" + field + "' must be an object");
        }
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    public List<Object> optList(String field) {
        Object value = data.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof List)) {
            throw new BodyValidationException("field '" + field + "' must be an array");
        }
        return (List<Object>) value;
    }

    public boolean has(String field) {
        return data.containsKey(field) && data.get(field) != null;
    }
}
