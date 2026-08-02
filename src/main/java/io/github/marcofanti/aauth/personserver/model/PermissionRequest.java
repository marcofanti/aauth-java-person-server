package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

public record PermissionRequest(
        String action, String description, Map<String, Object> parameters, MissionRef mission, String agentId) {}
