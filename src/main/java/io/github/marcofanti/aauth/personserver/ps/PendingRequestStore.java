package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import java.util.List;
import java.util.Map;

/**
 * Backing store for pending URLs; not exposed as public REST
 * (protocol §Deferred Response State Machine).
 *
 * <p>The Python reference splits an ABC from implementation extras that every collaborator
 * uses anyway (record access, code lookup, listing). Java folds them into one port so the
 * SQL store can substitute for the memory store everywhere.
 */
public interface PendingRequestStore {

    /** Snapshot of a non-terminal state update; null fields are left unchanged. */
    record PendingUpdate(
            PendingStatus status,
            RequirementLevel requirement,
            String clarification,
            Integer timeout,
            List<String> options) {

        public static PendingUpdate ofStatus(PendingStatus status) {
            return new PendingUpdate(status, null, null, null, null);
        }

        public static PendingUpdate ofRequirement(RequirementLevel requirement) {
            return new PendingUpdate(null, requirement, null, null, null);
        }
    }

    /** Parameters for an agent-facing interaction pending ({@code POST /interaction}). */
    record InteractionPendingSpec(
            String agentId,
            String interactionType,
            String ownerId,
            String missionS256,
            String summary,
            String question,
            String relayUrl,
            String relayCode,
            String description) {}

    /** Parameters for a deferred permission decision (Layer 2, outside approved_tools). */
    record PermissionPendingSpec(
            String agentId,
            String ownerId,
            String missionS256,
            String action,
            String description,
            Map<String, Object> parameters) {}

    /** Create a new token pending; returns {@code pendingId} (path segment). */
    String createPending(TokenRequest request);

    /** Create a new mission pending; returns {@code pendingId}. */
    String createPending(MissionProposal proposal);

    /** Deferred user step for {@code POST /interaction} (agent-facing). */
    String createInteractionPending(InteractionPendingSpec spec);

    /** Deferred user step for {@code POST /permission} outside approved_tools (Layer 2). */
    String createPermissionPending(PermissionPendingSpec spec);

    /**
     * Return current deferred snapshot or terminal success (token or mission).
     * {@code forPoll} enables polling semantics (rate limiting) for GET on the pending URL.
     */
    PendingStoreValue getPending(String pendingId, boolean forPoll);

    /** Update non-terminal pending state (e.g. status → interacting). */
    void updatePending(String pendingId, PendingUpdate update);

    /** Mark success; subsequent reads reflect completion. */
    void resolvePending(String pendingId, PendingStoreValue result);

    /** Record terminal failure (maps to 403/500 in the HTTP layer). */
    void failPending(String pendingId, String error);

    /** Cancel: subsequent access returns 410 Gone per protocol. */
    void deletePending(String pendingId);

    /** Ensure the pending row belongs to this agent (else throw {@link NotFoundException}). */
    void assertAgentOwnsPending(String pendingId, String agentId);

    /** Optional redirect after consent (protocol §User Interaction). */
    void setCallbackUrl(String pendingId, String callbackUrl);

    /** Resolve a consent {@code code} to its pending record (rejects terminal rows). */
    PendingRecord lookupCode(String code);

    /** Pending record including internal fields (implementation helper). */
    PendingRecord getRecord(String pendingId);

    String getInteractionCode(String pendingId);

    /** Swap the resource token / justification on a token pending (updated request). */
    void replaceTokenRequest(String pendingId, String resourceToken, String justification);

    String interactionBaseUrl();

    /** Pending rows awaiting user interaction, scoped to legal owner. */
    List<PendingRecord> listInteractionPendingForOwner(String ownerId);

    /** All in-flight pending rows (not gone, not resolved, not failed). */
    List<Map<String, Object>> listOpenPendingForAdmin();
}
