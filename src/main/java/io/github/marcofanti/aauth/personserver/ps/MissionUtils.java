package io.github.marcofanti.aauth.personserver.ps;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.marcofanti.aauth.personserver.Json;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionProposal;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.model.ToolSpec;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Mission blob construction and s256 (SPEC §Mission Approval). */
public final class MissionUtils {

    public static final List<String> DEFAULT_CAPABILITIES = List.of("interaction");

    private static final DateTimeFormatter APPROVED_AT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private MissionUtils() {}

    public static String s256HashBytes(byte[] blob) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(blob);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing SHA-256", e);
        }
    }

    /** Build {@code agent} string for mission JSON ({@code aauth:local@host}). */
    public static String agentClaimForMissionBlob(String agentId, String psIssuer) {
        String host = URI.create(psIssuer).getHost();
        if (host == null || host.isEmpty()) {
            host = "localhost";
        }
        StringBuilder safe = new StringBuilder();
        for (char c : agentId.toCharArray()) {
            boolean keep = Character.isLetterOrDigit(c) || c == '-' || c == '_';
            safe.append(keep ? c : '_');
            if (safe.length() >= 128) {
                break;
            }
        }
        return "aauth:" + safe + "@" + host;
    }

    public static List<Map<String, String>> approvedToolsFromProposal(List<ToolSpec> tools) {
        if (tools == null || tools.isEmpty()) {
            return null;
        }
        List<Map<String, String>> out = new ArrayList<>();
        for (ToolSpec tool : tools) {
            out.add(Map.of("name", tool.name(), "description", tool.description()));
        }
        return out;
    }

    /** Canonical JSON bytes for s256 (SPEC: hash of exact response body bytes). */
    public static byte[] buildMissionBlobBytes(
            String approver,
            String agent,
            String approvedAtIso,
            String description,
            List<Map<String, String>> approvedTools,
            List<String> capabilities) {
        Map<String, Object> obj = new LinkedHashMap<>();
        obj.put("approver", approver);
        obj.put("agent", agent);
        obj.put("approved_at", approvedAtIso);
        obj.put("description", description);
        if (approvedTools != null) {
            obj.put("approved_tools", approvedTools);
        }
        if (capabilities != null) {
            obj.put("capabilities", capabilities);
        }
        try {
            return Json.CANONICAL.writeValueAsString(obj).getBytes(StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize mission blob", e);
        }
    }

    /** Build an active mission from a proposal (PS issuer URL required for approver field). */
    public static Mission missionFromProposal(MissionProposal proposal, String psIssuer) {
        return missionFromProposal(proposal, psIssuer, DEFAULT_CAPABILITIES);
    }

    public static Mission missionFromProposal(MissionProposal proposal, String psIssuer, List<String> capabilities) {
        String description = proposal.description().stripTrailing();
        List<Map<String, String>> approvedTools = approvedToolsFromProposal(proposal.tools());
        List<String> caps = (capabilities == null || capabilities.isEmpty()) ? null : List.copyOf(capabilities);
        Instant approvedAt = Instant.now();
        String approvedAtIso = APPROVED_AT.format(approvedAt);
        String approver = stripTrailingSlash(psIssuer);

        String agentClaim = agentClaimForMissionBlob(proposal.agentId(), psIssuer);
        byte[] blob = buildMissionBlobBytes(approver, agentClaim, approvedAtIso, description, approvedTools, caps);
        return new Mission(
                s256HashBytes(blob),
                blob,
                MissionState.ACTIVE,
                proposal.agentId(),
                approvedAt,
                proposal.ownerHint(),
                approver,
                description,
                approvedTools,
                caps);
    }

    /** Deserialize mission fields for API responses (same logical content as blobBytes). */
    public static Map<String, Object> missionBlobDict(Mission mission) {
        return Json.readMap(new String(mission.blobBytes(), StandardCharsets.UTF_8));
    }

    public static String stripTrailingSlash(String url) {
        String out = url;
        while (out.endsWith("/")) {
            out = out.substring(0, out.length() - 1);
        }
        return out;
    }
}
