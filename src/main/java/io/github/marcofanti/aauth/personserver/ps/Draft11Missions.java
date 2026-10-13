package io.github.marcofanti.aauth.personserver.ps;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.Identifiers;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionLogKind;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.PersonTokenRequest;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore.PendingUpdate;
import io.github.marcofanti.aauth.personserver.ps.web.PsAuth.TokenAgentContext;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Draft-11 missions (§8): the blob carries no approver or capabilities, the approval response
 * returns the blob bytes and person tokens, missions may expire, and termination reasons are
 * recorded in the mission log beside the immutable blob. Unless missions are auto-approved, a
 * proposal waits for the person (§8.1, 202) and the agent polls for the approval.
 */
public final class Draft11Missions {

    private static final DateTimeFormatter ISO_SECONDS =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);
    private static final Pattern S256 = Pattern.compile("[A-Za-z0-9_-]{43}");

    /** A draft-11 mission proposal (§8.1). */
    public record Proposal(String description, List<ToolSpec> tools, List<String> resources) {}

    /** The approval response (§8.2). */
    public record Approval(String s256, byte[] blob, List<String> capabilities, Map<String, String> personTokens) {

        public Map<String, Object> body() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("s256", s256);
            out.put("mission", Base64.getUrlEncoder().withoutPadding().encodeToString(blob));
            if (capabilities != null && !capabilities.isEmpty()) {
                out.put("capabilities", capabilities);
            }
            if (!personTokens.isEmpty()) {
                out.put("person_tokens", personTokens);
            }
            return out;
        }
    }

    /**
     * @param psOrigin this PS
     * @param person the person missions are approved for
     * @param lifetimeSeconds when set, every mission gets {@code expires_at} that far after
     *     approval (§8.2); {@code null} for missions that run until completed or revoked
     * @param autoApprove approve proposals at once rather than asking the person
     */
    public record Settings(String psOrigin, String person, Long lifetimeSeconds, boolean autoApprove) {}

    /** What a deferred proposal keeps of the agent until the person decides. */
    public record PendingProposal(Map<String, Object> agentCnfJwk, Long agentTokenExp, List<String> resources) {

        public PendingProposal {
            resources = List.copyOf(resources);
        }
    }

    /** The answer to a proposal: the approval, or a 202 while the person reviews it. */
    public sealed interface Outcome {

        record Approved(Approval approval) implements Outcome {}

        record Deferred(DeferredResponse deferred) implements Outcome {}
    }

    private final MissionStatePort missions;
    private final PersonTokenIssuer issuer;
    private final PendingRequestStore pending;
    private final String psOrigin;
    private final Settings settings;

    public Draft11Missions(
            MissionStatePort missions, PersonTokenIssuer issuer, PendingRequestStore pending, Settings settings) {
        this.missions = missions;
        this.issuer = issuer;
        this.pending = pending;
        this.psOrigin = MissionUtils.stripTrailingSlash(settings.psOrigin());
        this.settings = settings;
    }

    /** §8.1: approve the proposal, or defer it to the person. */
    public Outcome propose(TokenAgentContext agent, Proposal proposal) {
        List<String> resources = validate(agent, proposal);
        if (settings.autoApprove()) {
            return new Outcome.Approved(create(agent, proposal));
        }
        String pendingId = pending.createPending(
                new MissionProposal(agent.agentId(), proposal.description(), proposal.tools(), null));
        PendingRecord record = pending.getRecord(pendingId);
        record.draft11Mission = new PendingProposal(agent.agentCnfJwk(), agent.agentTokenExp(), resources);
        pending.saveRecord(record);
        pending.updatePending(pendingId, PendingUpdate.ofRequirement(RequirementLevel.INTERACTION));
        if (!(pending.getPending(pendingId, false) instanceof DeferredResponse deferred)) {
            throw new IllegalStateException("a new mission pending is not deferred");
        }
        return new Outcome.Deferred(deferred);
    }

    /** Approve a deferred proposal the person accepted (§8.2). */
    public Approval approve(PendingRecord record) {
        PendingProposal proposal = record.draft11Mission;
        TokenAgentContext agent = new TokenAgentContext(
                record.missionProposal.agentId(),
                null,
                proposal.agentCnfJwk(),
                true,
                null,
                proposal.agentTokenExp(),
                null);
        return create(
                agent,
                new Proposal(
                        record.missionProposal.description(), record.missionProposal.tools(), proposal.resources()));
    }

    private static List<String> validate(TokenAgentContext agent, Proposal proposal) {
        if (agent.agentCnfJwk() == null) {
            throw new ProblemError(400, "invalid_request", "mission proposals are signed with scheme=jwt");
        }
        if (proposal.description() == null || proposal.description().isBlank()) {
            throw new ProblemError(400, "invalid_request", "description is required");
        }
        return validResources(proposal.resources());
    }

    public Approval create(TokenAgentContext agent, Proposal proposal) {
        List<String> resources = validate(agent, proposal);
        Long lifetimeSeconds = settings.lifetimeSeconds();
        String person = settings.person();
        Instant approvedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expires = lifetimeSeconds == null ? null : approvedAt.plusSeconds(lifetimeSeconds);
        List<Map<String, String>> tools = MissionUtils.approvedToolsFromProposal(proposal.tools());

        Map<String, Object> blob = new LinkedHashMap<>();
        blob.put("agent", agent.agentId());
        blob.put("approved_at", ISO_SECONDS.format(approvedAt));
        blob.put("description", proposal.description().stripTrailing());
        if (expires != null) {
            blob.put("expires_at", ISO_SECONDS.format(expires));
        }
        if (tools != null) {
            blob.put("approved_tools", tools);
        }
        if (!resources.isEmpty()) {
            blob.put("approved_resources", resources);
        }
        byte[] bytes = canonical(blob);
        String s256 = MissionUtils.s256HashBytes(bytes);
        List<String> capabilities = MissionUtils.DEFAULT_CAPABILITIES;
        missions.setMission(new Mission(
                s256,
                bytes,
                MissionState.ACTIVE,
                agent.agentId(),
                approvedAt,
                person,
                psOrigin,
                proposal.description().stripTrailing(),
                tools,
                capabilities));
        missions.appendMissionLog(
                s256, new MissionLogEntry(approvedAt, MissionLogKind.MISSION_APPROVED, Map.of("draft", 11)));

        Long maxExp = earliest(agent.agentTokenExp(), expires == null ? null : expires.getEpochSecond());
        Map<String, String> personTokens = new LinkedHashMap<>();
        // An agent token that expired while the person reviewed leaves nothing to bind tokens to;
        // the agent requests person tokens after renewing it (§7.1).
        boolean agentTokenLive = maxExp == null || maxExp > Instant.now().getEpochSecond();
        for (String resource : agentTokenLive ? resources : List.<String>of()) {
            PersonTokenRequest request = new PersonTokenRequest(
                    agent.agentId(), agent.agentCnfJwk(), resource, s256, null, maxExp, null, null, null, null, null);
            personTokens.put(resource, issuer.approveAndIssue(request, person).personToken());
        }
        return new Approval(s256, bytes, capabilities, personTokens);
    }

    /** §8.4: record an update in the log; the blob and mission_s256 do not change. */
    public String update(Mission mission, String description) {
        if (description == null || description.isBlank()) {
            throw new ProblemError(400, "invalid_request", "update requires a description");
        }
        Map<String, Object> update = new LinkedHashMap<>();
        update.put("accepted_at", ISO_SECONDS.format(Instant.now()));
        update.put("description", description.stripTrailing());
        byte[] bytes = canonical(update);
        String s256 = MissionUtils.s256HashBytes(bytes);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("s256", s256);
        payload.put("update", Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        missions.appendMissionLog(
                mission.s256(), new MissionLogEntry(Instant.now(), MissionLogKind.MISSION_UPDATE, payload));
        return s256;
    }

    private static List<String> validResources(List<String> resources) {
        List<String> out = new ArrayList<>();
        if (resources == null) {
            return out;
        }
        for (String resource : resources) {
            try {
                String normalized = Identifiers.validateServerIdentifier(MissionUtils.stripTrailingSlash(resource));
                if (!out.contains(normalized)) {
                    out.add(normalized);
                }
            } catch (IllegalArgumentException e) {
                throw new ProblemError(400, "invalid_request", "invalid resource " + resource + ": " + e.getMessage());
            }
        }
        return out;
    }

    private static byte[] canonical(Map<String, Object> value) {
        try {
            return Json.CANONICAL.writeValueAsString(value).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize mission JSON", e);
        }
    }

    private static Long earliest(Long a, Long b) {
        if (a == null) {
            return b;
        }
        return b == null ? a : Math.min(a, b);
    }
}
