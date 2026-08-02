package io.github.marcofanti.aauth.personserver.model;

import java.util.List;

public record MissionProposal(String agentId, String description, List<ToolSpec> tools, String ownerHint) {

    public MissionProposal(String agentId, String description) {
        this(agentId, description, List.of(), null);
    }
}
