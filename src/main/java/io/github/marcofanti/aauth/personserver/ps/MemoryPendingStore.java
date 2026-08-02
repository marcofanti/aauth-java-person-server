package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link PendingRequestStore}. */
public final class MemoryPendingStore implements PendingRequestStore {

    /**
     * Minimum interval between polls; below this returns 429 slow_down per spec backoff
     * guidance. Deferred 202 responses must not advertise Retry-After: 0 while this limit
     * applies — clients skip sleep on 0 and poll immediately, yielding 429 on the next GET.
     */
    private static final long MIN_POLL_INTERVAL_NANOS = 50_000_000L;

    private static final int DEFAULT_DEFERRED_RETRY_AFTER = 1;

    /** Human consent entry (browser); that page calls {@code GET /consent?code=...}. */
    public static final String CONSENT_UI_PATH = "/ui/consent.html";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final PsBackend backend;
    private final String interactionBaseUrl;
    private final int defaultTtlSeconds;

    public MemoryPendingStore(PsBackend backend, String interactionBaseUrl, int defaultTtlSeconds) {
        this.backend = backend;
        this.interactionBaseUrl = MissionUtils.stripTrailingSlash(interactionBaseUrl);
        this.defaultTtlSeconds = defaultTtlSeconds;
    }

    @Override
    public String interactionBaseUrl() {
        return interactionBaseUrl;
    }

    public static String newPendingId() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        String id =
                Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).replace("-", "");
        return id.substring(0, Math.min(16, id.length()));
    }

    public static String newInteractionCode() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String pendingPath(String pendingId) {
        return interactionBaseUrl + "/pending/" + pendingId;
    }

    private String ownerForTokenRequest(TokenRequest request) {
        for (Mission mission : backend.listAllMissions()) {
            if (mission.agentId().equals(request.agentId()) && mission.ownerId() != null) {
                return mission.ownerId();
            }
        }
        return null;
    }

    private synchronized PendingRecord register(PendingRecord record) {
        backend.pending.put(record.pendingId, record);
        backend.codeIndex.put(record.interactionCode, record.pendingId);
        return record;
    }

    @Override
    public String createPending(TokenRequest request) {
        PendingRecord record =
                new PendingRecord(newPendingId(), newInteractionCode(), "token", Instant.now(), defaultTtlSeconds);
        record.tokenRequest = request;
        record.ownerId = ownerForTokenRequest(request);
        return register(record).pendingId;
    }

    @Override
    public String createPending(MissionProposal proposal) {
        PendingRecord record =
                new PendingRecord(newPendingId(), newInteractionCode(), "mission", Instant.now(), defaultTtlSeconds);
        record.missionProposal = proposal;
        record.ownerId = proposal.ownerHint();
        return register(record).pendingId;
    }

    @Override
    public String createInteractionPending(InteractionPendingSpec spec) {
        PendingRecord record = new PendingRecord(
                newPendingId(), newInteractionCode(), "interaction", Instant.now(), defaultTtlSeconds);
        record.ownerId = spec.ownerId();
        record.pendingAgentId = spec.agentId();
        record.interactionType = spec.interactionType();
        record.interactionSummary = spec.summary();
        record.interactionQuestion = spec.question();
        record.relayUrl = spec.relayUrl();
        record.relayCode = spec.relayCode();
        record.missionS256 = spec.missionS256();
        record.interactionDescription = spec.description();
        return register(record).pendingId;
    }

    @Override
    public String createPermissionPending(PermissionPendingSpec spec) {
        PendingRecord record =
                new PendingRecord(newPendingId(), newInteractionCode(), "permission", Instant.now(), defaultTtlSeconds);
        record.ownerId = spec.ownerId();
        record.pendingAgentId = spec.agentId();
        record.missionS256 = spec.missionS256();
        record.permissionAction = spec.action();
        record.permissionDescription = spec.description();
        record.permissionParameters = spec.parameters();
        return register(record).pendingId;
    }

    private synchronized PendingRecord require(String pendingId) {
        PendingRecord record = backend.pending.get(pendingId);
        if (record == null) {
            throw new NotFoundException();
        }
        return record;
    }

    @Override
    public synchronized void assertAgentOwnsPending(String pendingId, String agentId) {
        PendingRecord record = require(pendingId);
        String owner = record.agentId();
        if (owner == null || !owner.equals(agentId)) {
            throw new NotFoundException();
        }
    }

    private synchronized void checkTtl(PendingRecord record) {
        if (record.terminal != null || record.gone || record.failure != null) {
            return;
        }
        long elapsed = Duration.between(record.createdAt, Instant.now()).toSeconds();
        if (elapsed <= record.ttlSeconds) {
            return;
        }
        if (record.status == PendingStatus.INTERACTING) {
            failPending(record.pendingId, "abandoned");
        } else {
            failPending(record.pendingId, "expired");
        }
    }

    private synchronized void rateLimitPoll(PendingRecord record) {
        long now = System.nanoTime();
        if (record.lastPollNanos != null && now - record.lastPollNanos < MIN_POLL_INTERVAL_NANOS) {
            throw new SlowDownException();
        }
        record.lastPollNanos = now;
    }

    @Override
    public synchronized PendingStoreValue getPending(String pendingId, boolean forPoll) {
        PendingRecord record = require(pendingId);
        checkTtl(record);
        if (record.gone) {
            throw new PendingGoneException();
        }
        if (record.failure != null) {
            if ("expired".equals(record.failure)) {
                throw new PendingExpiredException();
            }
            throw new PendingDeniedException(record.failure);
        }
        if (record.terminal != null) {
            if (record.delivered) {
                throw new NotFoundException();
            }
            record.delivered = true;
            return record.terminal;
        }
        if (forPoll) {
            rateLimitPoll(record);
        }
        return toDeferred(record);
    }

    @Override
    public synchronized String getInteractionCode(String pendingId) {
        return require(pendingId).interactionCode;
    }

    @Override
    public synchronized void replaceTokenRequest(String pendingId, String resourceToken, String justification) {
        PendingRecord record = require(pendingId);
        if (record.tokenRequest == null) {
            throw new IllegalStateException("not a token pending");
        }
        TokenRequest previous = record.tokenRequest;
        record.tokenRequest = new TokenRequest(
                previous.agentId(),
                resourceToken,
                justification,
                previous.upstreamToken(),
                previous.loginHint(),
                previous.tenant(),
                previous.domainHint(),
                previous.mission(),
                previous.agentCnfJwk(),
                previous.agentJkt(),
                previous.secureMode());
    }

    private DeferredResponse toDeferred(PendingRecord record) {
        String interactionUrl = null;
        String showCode = null;
        if (record.requirement == RequirementLevel.INTERACTION) {
            interactionUrl = interactionBaseUrl + CONSENT_UI_PATH;
            showCode = record.interactionCode;
        }
        return new DeferredResponse(
                record.pendingId,
                pendingPath(record.pendingId),
                DEFAULT_DEFERRED_RETRY_AFTER,
                record.requirement,
                interactionUrl,
                showCode,
                record.clarification,
                record.timeout,
                record.options,
                record.status);
    }

    @Override
    public synchronized void updatePending(String pendingId, PendingUpdate update) {
        PendingRecord record = require(pendingId);
        if (update.status() != null) {
            record.status = update.status();
        }
        if (update.requirement() != null) {
            record.requirement = update.requirement();
        }
        if (update.clarification() != null) {
            record.clarification = update.clarification();
        }
        if (update.timeout() != null) {
            record.timeout = update.timeout();
        }
        if (update.options() != null) {
            record.options = update.options();
        }
    }

    @Override
    public synchronized void setCallbackUrl(String pendingId, String callbackUrl) {
        require(pendingId).callbackUrl = callbackUrl;
    }

    @Override
    public synchronized void resolvePending(String pendingId, PendingStoreValue result) {
        PendingRecord record = require(pendingId);
        record.terminal = result;
        record.failure = null;
        invalidateCodeFor(pendingId);
    }

    @Override
    public synchronized void failPending(String pendingId, String error) {
        PendingRecord record = require(pendingId);
        record.failure = error;
        record.terminal = null;
        invalidateCodeFor(pendingId);
    }

    @Override
    public synchronized void deletePending(String pendingId) {
        PendingRecord record = require(pendingId);
        record.gone = true;
        record.terminal = null;
        invalidateCodeFor(pendingId);
    }

    @Override
    public synchronized PendingRecord lookupCode(String code) {
        String pendingId = backend.codeIndex.get(code);
        if (pendingId == null) {
            throw new InvalidInteractionCodeException();
        }
        PendingRecord record = require(pendingId);
        checkTtl(record);
        if (record.gone || record.failure != null || record.terminal != null) {
            backend.codeIndex.remove(code);
            throw new InvalidInteractionCodeException();
        }
        return record;
    }

    private void invalidateCodeFor(String pendingId) {
        PendingRecord record = backend.pending.get(pendingId);
        if (record != null) {
            backend.codeIndex.remove(record.interactionCode);
        }
    }

    @Override
    public synchronized PendingRecord getRecord(String pendingId) {
        return require(pendingId);
    }

    @Override
    public synchronized List<PendingRecord> listInteractionPendingForOwner(String ownerId) {
        List<PendingRecord> out = new ArrayList<>();
        for (PendingRecord record : backend.pending.values()) {
            if (record.gone || record.terminal != null) {
                continue;
            }
            if (record.requirement != RequirementLevel.INTERACTION) {
                continue;
            }
            if (record.ownerId == null || !record.ownerId.equals(ownerId)) {
                continue;
            }
            out.add(record);
        }
        out.sort(Comparator.comparing(record -> record.pendingId));
        return out;
    }

    @Override
    public synchronized List<Map<String, Object>> listOpenPendingForAdmin() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (PendingRecord record : backend.pending.values()) {
            if (record.gone || record.terminal != null || record.failure != null) {
                continue;
            }
            String agentId = record.agentId() != null ? record.agentId() : "";
            Map<String, Object> claims = record.verifiedResourceClaims;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pending_id", record.pendingId);
            row.put("kind", record.kind);
            row.put("status", record.status.value());
            row.put("requirement", record.requirement != null ? record.requirement.value() : null);
            row.put("agent_id", agentId);
            row.put("owner_id", record.ownerId);
            row.put("code", record.requirement == RequirementLevel.INTERACTION ? record.interactionCode : null);
            row.put("interaction_url", interactionBaseUrl + CONSENT_UI_PATH);
            row.put("pending_url", pendingPath(record.pendingId));
            row.put("justification", record.tokenRequest != null ? record.tokenRequest.justification() : null);
            row.put("resource_iss", claims != null ? claims.get("iss") : null);
            row.put("resource_scope", claims != null ? claims.get("scope") : null);
            out.add(row);
        }
        out.sort(Comparator.comparing(row -> (String) row.get("pending_id")));
        return out;
    }
}
