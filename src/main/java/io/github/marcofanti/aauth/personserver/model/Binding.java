package io.github.marcofanti.aauth.personserver.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Person-approved binding of an agent id ({@code aauth:<uuid>@<domain>}) to one or more
 * stable key thumbprints ({@code urn:jkt:sha-256:...}).
 */
public record Binding(
        String agentId, String agentName, Instant createdAt, List<String> stableKeyThumbprints, boolean revoked) {

    public Binding withRevoked(boolean newRevoked) {
        return new Binding(agentId, agentName, createdAt, stableKeyThumbprints, newRevoked);
    }

    public Binding withAddedThumbprint(String jkt) {
        List<String> thumbprints = new ArrayList<>(stableKeyThumbprints);
        thumbprints.add(jkt);
        return new Binding(agentId, agentName, createdAt, List.copyOf(thumbprints), revoked);
    }
}
