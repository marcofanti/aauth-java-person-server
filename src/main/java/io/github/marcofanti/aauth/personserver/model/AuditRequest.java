package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

public record AuditRequest(
        MissionRef mission,
        String action,
        String description,
        Map<String, Object> parameters,
        Map<String, Object> result,
        String agentId) {}
