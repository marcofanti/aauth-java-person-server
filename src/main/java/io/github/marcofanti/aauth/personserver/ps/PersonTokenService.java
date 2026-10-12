package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.TokenException;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.ps.web.PsAuth.TokenAgentContext;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The draft-11 person token endpoint (§7.1): validates the request, decides whether the person
 * must be asked (first use of a resource), and issues or defers.
 */
public final class PersonTokenService {

    private static final Logger log = LoggerFactory.getLogger(PersonTokenService.class);

    /** Distinct live resources one agent may hold person tokens for (§7.1 SHOULD rate-limit). */
    static final int MAX_DISTINCT_RESOURCES = 100;

    private static final String INTERACTION = "interaction";

    /** Parsed request parameters (§7.1). */
    public record Params(
            String resource,
            String missionS256,
            String subagentToken,
            String upstreamToken,
            List<String> capabilities,
            String tenant,
            String justification) {}

    /** What the endpoint returns: a token now, or a 202 for the person's first-use approval. */
    public sealed interface Outcome {
        record Issued(PersonTokenIssuer.Issued token) implements Outcome {}

        record Deferred(DeferredResponse deferred) implements Outcome {}
    }

    /** Collaborators, grouped to keep the constructor small. */
    public record Deps(
            MissionStatePort missions,
            PendingRequestStore pending,
            PersonTokenIssuer issuer,
            Function<String, Map<String, Object>> agentJwks,
            Function<String, Map<String, Object>> resourceMetadata,
            UpstreamTokens upstreamTokens) {}

    private final Deps deps;
    private final String person;
    private final boolean autoApprove;

    public PersonTokenService(Deps deps, String person, boolean autoApprove) {
        this.deps = deps;
        this.person = person;
        this.autoApprove = autoApprove;
    }

    public Outcome request(TokenAgentContext agent, Params params) {
        if (agent.agentCnfJwk() == null) {
            throw new ProblemError(
                    400, "invalid_request", "a person token binds the agent's key: sign with scheme=jwt");
        }
        String resource = validResource(params.resource());
        UpstreamTokens.Upstream upstream = upstreamOf(agent, params);
        // §7.1 Which person: the bound person, or with upstream_token the person it was issued for.
        String forPerson = upstream != null ? upstream.person() : person;
        String missionS256 = upstream != null ? upstream.missionS256() : params.missionS256();
        Mission mission = activeMissionOf(upstream != null ? upstream.callingAgent() : agent.agentId(), missionS256);
        Holder holder = holderFor(agent, params.subagentToken());

        if (deps.issuer().distinctLiveResources(holder.agentId(), resource) >= MAX_DISTINCT_RESOURCES) {
            throw new ProblemError(
                    429, ProblemError.RATE_LIMITED, "too many distinct resources requested by this agent");
        }

        Map<String, Object> metadata = fetchMetadata(resource);
        PersonTokenRequest request = new PersonTokenRequest(
                holder.agentId(),
                holder.cnfJwk(),
                resource,
                missionS256,
                params.tenant(),
                earliest(
                        earliest(holder.maxExp(), Draft11MissionStatus.capFor(mission)),
                        upstream != null ? upstream.exp() : null),
                string(metadata, "name"),
                string(metadata, "description"),
                string(metadata, "access_mode"),
                params.justification(),
                upstream != null ? new PersonTokenRequest.Upstream(upstream.iss(), upstream.jti()) : null);

        if (autoApprove || deps.issuer().isApproved(forPerson, resource)) {
            return new Outcome.Issued(deps.issuer().issue(request, forPerson));
        }
        List<String> capabilities = params.capabilities() != null
                ? params.capabilities()
                : mission != null && mission.capabilities() != null ? mission.capabilities() : List.of();
        if (!capabilities.contains(INTERACTION)) {
            throw new ProblemError(
                    403,
                    ProblemError.USER_UNREACHABLE,
                    "first use of this resource needs the person's approval and the agent did not declare"
                            + " the interaction capability");
        }
        String pendingId = deps.pending().createPersonTokenPending(request, forPerson);
        PendingStoreValue value = deps.pending().getPending(pendingId, false);
        if (!(value instanceof DeferredResponse deferred)) {
            throw new IllegalStateException("new person token pending " + pendingId + " is not deferred");
        }
        return new Outcome.Deferred(deferred);
    }

    /**
     * §7.1, §10.1.1: verify a call-chaining upstream token; the intermediary sends no mission or
     * sub-agent of its own, since the upstream token carries the mission.
     */
    private UpstreamTokens.Upstream upstreamOf(TokenAgentContext agent, Params params) {
        if (params.upstreamToken() == null) {
            return null;
        }
        if (params.missionS256() != null || params.subagentToken() != null) {
            throw new ProblemError(
                    400, "invalid_request", "upstream_token is sent without mission_s256 or subagent_token");
        }
        return deps.upstreamTokens().verify(params.upstreamToken(), agent.agentIss());
    }

    private static String validResource(String resource) {
        if (resource == null || resource.isBlank()) {
            throw new ProblemError(400, "invalid_request", "resource is required");
        }
        try {
            return MissionUtils.stripTrailingSlash(Identifiers.validateServerUrl(resource));
        } catch (IllegalArgumentException e) {
            throw new ProblemError(400, "invalid_request", "invalid resource: " + e.getMessage());
        }
    }

    /** §7.1: the mission must exist, be active, and belong to this agent. */
    private Mission activeMissionOf(String agentId, String missionS256) {
        if (missionS256 == null) {
            return null;
        }
        return new Draft11MissionStatus(deps.missions()).requireActiveParameter(missionS256, agentId);
    }

    /** Who the token is for: the signing agent, or the sub-agent its subagent_token names (§10.2). */
    private record Holder(String agentId, Map<String, Object> cnfJwk, Long maxExp) {}

    private Holder holderFor(TokenAgentContext agent, String subagentToken) {
        if (subagentToken == null) {
            return new Holder(agent.agentId(), agent.agentCnfJwk(), agent.agentTokenExp());
        }
        Map<String, Object> claims;
        try {
            claims = AgentTokens.verify(subagentToken, deps.agentJwks(), null);
        } catch (TokenException e) {
            String message = String.valueOf(e.getMessage());
            String code = message.toLowerCase(Locale.ROOT).contains("expired")
                    ? ProblemError.EXPIRED_SUBAGENT_TOKEN
                    : ProblemError.INVALID_SUBAGENT_TOKEN;
            throw new ProblemError(400, code, message);
        }
        if (!Objects.equals(claims.get("parent_agent"), agent.agentId())) {
            throw new ProblemError(
                    400, ProblemError.INVALID_SUBAGENT_TOKEN, "subagent_token's parent_agent is not the signing agent");
        }
        if (!Objects.equals(claims.get("iss"), agent.agentIss())) {
            throw new ProblemError(
                    400, ProblemError.INVALID_SUBAGENT_TOKEN, "subagent_token's iss differs from the signing agent's");
        }
        Object cnf = claims.get("cnf");
        if (!(cnf instanceof Map<?, ?> cnfMap) || !(cnfMap.get("jwk") instanceof Map<?, ?> jwk)) {
            throw new ProblemError(400, ProblemError.INVALID_SUBAGENT_TOKEN, "subagent_token has no cnf.jwk");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> subKey = (Map<String, Object>) jwk;
        Long subExp = claims.get("exp") instanceof Number n ? n.longValue() : null;
        return new Holder(String.valueOf(claims.get("sub")), subKey, earliest(agent.agentTokenExp(), subExp));
    }

    private Map<String, Object> fetchMetadata(String resource) {
        if (deps.resourceMetadata() == null) {
            return Map.of();
        }
        try {
            Map<String, Object> metadata = deps.resourceMetadata().apply(resource);
            return metadata == null ? Map.of() : metadata;
        } catch (RuntimeException e) {
            log.info("resource metadata for {} unavailable ({}); consent shows the URL only", resource, e.getMessage());
            return Map.of();
        }
    }

    private static Long earliest(Long a, Long b) {
        if (a == null) {
            return b;
        }
        return b == null ? a : Math.min(a, b);
    }

    private static String string(Map<String, Object> map, String key) {
        return map.get(key) instanceof String value ? value : null;
    }
}
