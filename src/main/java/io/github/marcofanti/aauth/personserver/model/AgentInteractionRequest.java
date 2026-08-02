package io.github.marcofanti.aauth.personserver.model;

/** {@code POST /interaction} (agent, signed). {@code type} is interaction | payment | question | completion. */
public record AgentInteractionRequest(
        String type,
        String description,
        String url,
        String code,
        String question,
        String summary,
        MissionRef mission,
        String agentId) {}
