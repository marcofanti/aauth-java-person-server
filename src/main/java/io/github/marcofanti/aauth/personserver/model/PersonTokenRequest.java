package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

/**
 * A verified draft-11 person token request (§7.1): the agent, the key the token binds, the
 * resource it names, and what the PS showed or will show the person about that resource.
 *
 * @param agentId the requesting (or, for a sub-agent request, the sub-) agent identifier
 * @param cnfJwk the public key the issued token binds via {@code cnf.jwk}
 * @param resource the resource identifier; becomes the token's {@code aud}
 * @param missionS256 the mission the agent operates under, or {@code null}
 * @param tenant the organization context to carry, or {@code null}
 * @param maxExp the latest permitted {@code exp} (agent token, mission), or {@code null}
 * @param resourceName the resource's metadata {@code name}, or {@code null}
 * @param resourceDescription the resource's metadata {@code description}, or {@code null}
 * @param resourceAccessMode the resource's metadata {@code access_mode}, or {@code null}
 * @param justification agent-asserted reason for the request, or {@code null}
 */
public record PersonTokenRequest(
        String agentId,
        Map<String, Object> cnfJwk,
        String resource,
        String missionS256,
        String tenant,
        Long maxExp,
        String resourceName,
        String resourceDescription,
        String resourceAccessMode,
        String justification) {}
