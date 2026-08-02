package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.PendingStatus;
import io.github.marcofanti.aauth.personserver.model.PendingStoreValue;
import io.github.marcofanti.aauth.personserver.model.RequirementLevel;
import io.github.marcofanti.aauth.personserver.model.TokenRequest;
import io.github.marcofanti.aauth.personserver.ps.InvalidInteractionCodeException;
import io.github.marcofanti.aauth.personserver.ps.MemoryPendingStore;
import io.github.marcofanti.aauth.personserver.ps.MissionStatePort;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.NotFoundException;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PendingExpiredException;
import io.github.marcofanti.aauth.personserver.ps.PendingGoneException;
import io.github.marcofanti.aauth.personserver.ps.PendingRecord;
import io.github.marcofanti.aauth.personserver.ps.PendingRequestStore;
import io.github.marcofanti.aauth.personserver.ps.SlowDownException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.sql.DataSource;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * SQL-backed {@link PendingRequestStore} — load-modify-save rows keyed by pending id,
 * mirroring the Python {@code DatabasePendingStore}. Records returned by
 * {@link #getRecord} are detached snapshots (Python parity); poll rate limiting stays
 * in-process because monotonic timestamps don't survive restarts.
 */
public final class SqlPendingStore implements PendingRequestStore {

    private static final long MIN_POLL_INTERVAL_NANOS = 50_000_000L;

    private final JdbcTemplate jdbc;
    private final MissionStatePort mission;
    private final String interactionBaseUrl;
    private final int defaultTtlSeconds;
    private final Map<String, Long> lastPollNanos = new ConcurrentHashMap<>();

    public SqlPendingStore(
            DataSource dataSource, MissionStatePort mission, String interactionBaseUrl, int defaultTtlSeconds) {
        this.jdbc = new JdbcTemplate(dataSource);
        this.mission = mission;
        this.interactionBaseUrl = MissionUtils.stripTrailingSlash(interactionBaseUrl);
        this.defaultTtlSeconds = defaultTtlSeconds;
    }

    @Override
    public String interactionBaseUrl() {
        return interactionBaseUrl;
    }

    private String pendingPath(String pendingId) {
        return interactionBaseUrl + "/pending/" + pendingId;
    }

    private static boolean isOpen(PendingRecord record) {
        return !record.gone && record.failure == null && record.terminal == null;
    }

    private void insert(PendingRecord record) {
        jdbc.update(
                "INSERT INTO ps_pending (pending_id, interaction_code, code_unusable, is_open, owner_id, "
                        + "requirement, record_json) VALUES (?,?,?,?,?,?,?)",
                record.pendingId,
                record.interactionCode,
                false,
                true,
                record.ownerId,
                record.requirement == null ? null : record.requirement.value(),
                PendingSerde.write(PendingSerde.recordToDict(record)));
    }

    private void save(PendingRecord record) {
        jdbc.update(
                "UPDATE ps_pending SET is_open = ?, owner_id = ?, requirement = ?, record_json = ? "
                        + "WHERE pending_id = ?",
                isOpen(record),
                record.ownerId,
                record.requirement == null ? null : record.requirement.value(),
                PendingSerde.write(PendingSerde.recordToDict(record)),
                record.pendingId);
    }

    private PendingRecord load(String pendingId) {
        List<String> rows = jdbc.query(
                "SELECT record_json FROM ps_pending WHERE pending_id = ?",
                (rs, rowNum) -> rs.getString("record_json"),
                pendingId);
        if (rows.isEmpty()) {
            return null;
        }
        return PendingSerde.recordFromDict(Json.readMap(rows.getFirst()));
    }

    private PendingRecord require(String pendingId) {
        PendingRecord record = load(pendingId);
        if (record == null) {
            throw new NotFoundException();
        }
        return record;
    }

    private String ownerForTokenRequest(TokenRequest request) {
        for (var candidate : mission.listAllMissions()) {
            if (candidate.agentId().equals(request.agentId()) && candidate.ownerId() != null) {
                return candidate.ownerId();
            }
        }
        return null;
    }

    @Override
    public String createPending(TokenRequest request) {
        PendingRecord record = new PendingRecord(newId(), newCode(), "token", Instant.now(), defaultTtlSeconds);
        record.tokenRequest = request;
        record.ownerId = ownerForTokenRequest(request);
        insert(record);
        return record.pendingId;
    }

    @Override
    public String createPending(MissionProposal proposal) {
        PendingRecord record = new PendingRecord(newId(), newCode(), "mission", Instant.now(), defaultTtlSeconds);
        record.missionProposal = proposal;
        record.ownerId = proposal.ownerHint();
        insert(record);
        return record.pendingId;
    }

    @Override
    public String createInteractionPending(InteractionPendingSpec spec) {
        PendingRecord record = new PendingRecord(newId(), newCode(), "interaction", Instant.now(), defaultTtlSeconds);
        record.ownerId = spec.ownerId();
        record.pendingAgentId = spec.agentId();
        record.interactionType = spec.interactionType();
        record.interactionSummary = spec.summary();
        record.interactionQuestion = spec.question();
        record.relayUrl = spec.relayUrl();
        record.relayCode = spec.relayCode();
        record.missionS256 = spec.missionS256();
        record.interactionDescription = spec.description();
        insert(record);
        return record.pendingId;
    }

    @Override
    public String createPermissionPending(PermissionPendingSpec spec) {
        PendingRecord record = new PendingRecord(newId(), newCode(), "permission", Instant.now(), defaultTtlSeconds);
        record.ownerId = spec.ownerId();
        record.pendingAgentId = spec.agentId();
        record.missionS256 = spec.missionS256();
        record.permissionAction = spec.action();
        record.permissionDescription = spec.description();
        record.permissionParameters = spec.parameters();
        insert(record);
        return record.pendingId;
    }

    private static String newId() {
        return MemoryPendingStore.newPendingId();
    }

    private static String newCode() {
        return MemoryPendingStore.newInteractionCode();
    }

    @Override
    public void assertAgentOwnsPending(String pendingId, String agentId) {
        PendingRecord record = require(pendingId);
        String owner = record.agentId();
        if (owner == null || !owner.equals(agentId)) {
            throw new NotFoundException();
        }
    }

    private void checkTtl(PendingRecord record) {
        if (!isOpen(record)) {
            return;
        }
        long elapsed = Duration.between(record.createdAt, Instant.now()).toSeconds();
        if (elapsed <= record.ttlSeconds) {
            return;
        }
        failPending(record.pendingId, record.status == PendingStatus.INTERACTING ? "abandoned" : "expired");
        record.failure = record.status == PendingStatus.INTERACTING ? "abandoned" : "expired";
    }

    @Override
    public PendingStoreValue getPending(String pendingId, boolean forPoll) {
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
            save(record);
            return record.terminal;
        }
        if (forPoll) {
            long now = System.nanoTime();
            Long last = lastPollNanos.get(pendingId);
            if (last != null && now - last < MIN_POLL_INTERVAL_NANOS) {
                throw new SlowDownException();
            }
            lastPollNanos.put(pendingId, now);
        }
        return toDeferred(record);
    }

    private DeferredResponse toDeferred(PendingRecord record) {
        String interactionUrl = null;
        String showCode = null;
        if (record.requirement == RequirementLevel.INTERACTION) {
            interactionUrl = interactionBaseUrl + MemoryPendingStore.CONSENT_UI_PATH;
            showCode = record.interactionCode;
        }
        return new DeferredResponse(
                record.pendingId,
                pendingPath(record.pendingId),
                1,
                record.requirement,
                interactionUrl,
                showCode,
                record.clarification,
                record.timeout,
                record.options,
                record.status);
    }

    @Override
    public void updatePending(String pendingId, PendingUpdate update) {
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
        save(record);
    }

    @Override
    public void setCallbackUrl(String pendingId, String callbackUrl) {
        PendingRecord record = require(pendingId);
        record.callbackUrl = callbackUrl;
        save(record);
    }

    @Override
    public void resolvePending(String pendingId, PendingStoreValue result) {
        PendingRecord record = require(pendingId);
        record.terminal = result;
        record.failure = null;
        save(record);
        invalidateCode(pendingId);
    }

    @Override
    public void failPending(String pendingId, String error) {
        PendingRecord record = require(pendingId);
        record.failure = error;
        record.terminal = null;
        save(record);
        invalidateCode(pendingId);
    }

    @Override
    public void deletePending(String pendingId) {
        PendingRecord record = require(pendingId);
        record.gone = true;
        record.terminal = null;
        save(record);
        invalidateCode(pendingId);
    }

    private void invalidateCode(String pendingId) {
        jdbc.update("UPDATE ps_pending SET code_unusable = TRUE WHERE pending_id = ?", pendingId);
    }

    @Override
    public PendingRecord lookupCode(String code) {
        List<String> ids = jdbc.query(
                "SELECT pending_id FROM ps_pending WHERE interaction_code = ? AND code_unusable = FALSE",
                (rs, rowNum) -> rs.getString("pending_id"),
                code);
        if (ids.isEmpty()) {
            throw new InvalidInteractionCodeException();
        }
        PendingRecord record = require(ids.getFirst());
        checkTtl(record);
        if (record.gone || record.failure != null || record.terminal != null) {
            invalidateCode(record.pendingId);
            throw new InvalidInteractionCodeException();
        }
        return record;
    }

    @Override
    public PendingRecord getRecord(String pendingId) {
        return require(pendingId);
    }

    @Override
    public String getInteractionCode(String pendingId) {
        return require(pendingId).interactionCode;
    }

    @Override
    public void replaceTokenRequest(String pendingId, String resourceToken, String justification) {
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
        save(record);
    }

    @Override
    public List<PendingRecord> listInteractionPendingForOwner(String ownerId) {
        List<String> ids = jdbc.query(
                "SELECT pending_id FROM ps_pending WHERE is_open = TRUE AND owner_id = ? AND requirement = ?",
                (rs, rowNum) -> rs.getString("pending_id"),
                ownerId,
                RequirementLevel.INTERACTION.value());
        List<PendingRecord> out = new ArrayList<>();
        for (String id : ids) {
            PendingRecord record = load(id);
            if (record == null || !isOpen(record)) {
                continue;
            }
            out.add(record);
        }
        out.sort(Comparator.comparing(record -> record.pendingId));
        return out;
    }

    @Override
    public List<Map<String, Object>> listOpenPendingForAdmin() {
        List<String> rows = jdbc.query(
                "SELECT record_json FROM ps_pending WHERE is_open = TRUE", (rs, rowNum) -> rs.getString("record_json"));
        List<Map<String, Object>> out = new ArrayList<>();
        for (String json : rows) {
            PendingRecord record = PendingSerde.recordFromDict(Json.readMap(json));
            if (!isOpen(record)) {
                continue;
            }
            Map<String, Object> claims = record.verifiedResourceClaims;
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("pending_id", record.pendingId);
            row.put("kind", record.kind);
            row.put("status", record.status.value());
            row.put("requirement", record.requirement != null ? record.requirement.value() : null);
            row.put("agent_id", record.agentId() != null ? record.agentId() : "");
            row.put("owner_id", record.ownerId);
            row.put("code", record.requirement == RequirementLevel.INTERACTION ? record.interactionCode : null);
            row.put("interaction_url", interactionBaseUrl + MemoryPendingStore.CONSENT_UI_PATH);
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
