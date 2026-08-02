package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.MissionLogEntry;
import io.github.marcofanti.aauth.personserver.model.MissionState;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.TrustedAgentServer;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.HttpError;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Admin mission control, pending overview, consent scopes, and trust registry. */
@Profile({"default", "portal", "ps"})
@RestController
public class PsAdminController {

    private final PsContainer ps;
    private final PsAuth auth;
    private final PsSettings settings;

    public PsAdminController(PsContainer ps, PsAuth auth, PsSettings settings) {
        this.ps = ps;
        this.auth = auth;
        this.settings = settings;
    }

    static Map<String, Object> missionDetailWithLog(Mission mission, List<MissionLogEntry> log) {
        Map<String, Object> detail = PsEncoding.missionDetailDict(mission);
        List<Map<String, Object>> entries = new ArrayList<>();
        for (MissionLogEntry entry : log) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("ts", entry.ts().toString());
            row.put("kind", entry.kind().value());
            row.put("payload", entry.payload());
            entries.add(row);
        }
        detail.put("log", entries);
        return detail;
    }

    static MissionState requireTerminatedState(byte[] raw) {
        BodyReader body = BodyReader.parse(raw);
        String state = body.requireString("state");
        if (!MissionState.TERMINATED.value().equals(state)) {
            throw new HttpError(400, "PATCH only supports target state terminated, got: '" + state + "'");
        }
        return MissionState.TERMINATED;
    }

    @GetMapping("/missions")
    public List<Map<String, Object>> listMissions(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam(value = "agent_id", required = false) String agentId,
            @RequestParam(value = "state", required = false) String state) {
        auth.requireAdmin(authorization);
        MissionState missionState = PsEncoding.missionStateFromQuery(state);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Mission mission : ps.missionControl().listMissions(agentId, missionState)) {
            out.add(PsEncoding.missionListDict(mission));
        }
        return out;
    }

    @GetMapping("/missions/{s256}")
    public Map<String, Object> inspectMission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("s256") String s256) {
        auth.requireAdmin(authorization);
        Mission mission = ps.missionControl().inspectMission(s256);
        return missionDetailWithLog(mission, ps.missionControl().missionLog(s256));
    }

    @PatchMapping("/missions/{s256}")
    public Map<String, Object> patchMission(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("s256") String s256,
            @RequestBody(required = false) byte[] raw) {
        auth.requireAdmin(authorization);
        requireTerminatedState(raw);
        Mission mission;
        try {
            mission = ps.missionControl().terminateMission(s256);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
        return PsEncoding.missionDetailDict(mission);
    }

    @GetMapping("/admin/pending")
    public List<Map<String, Object>> adminListPending(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requireAdmin(authorization);
        return ps.pendingStore().listOpenPendingForAdmin();
    }

    @GetMapping("/admin/consent-scopes")
    public Map<String, Object> getConsentScopes(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requireAdmin(authorization);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("scopes", ps.consentScopes().getScopes());
        return out;
    }

    @PostMapping("/admin/consent-scopes")
    public ResponseEntity<Map<String, Object>> addConsentScope(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) byte[] raw) {
        auth.requireAdmin(authorization);
        BodyReader body = BodyReader.parse(raw);
        String scope = body.optString("scope");
        scope = scope == null ? "" : scope.strip();
        if (scope.isEmpty()) {
            throw new HttpError(400, "scope field required and must be non-empty");
        }
        if (!ps.consentScopes().addScope(scope)) {
            throw new HttpError(409, "Scope '" + scope + "' already exists");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("scope", scope);
        out.put("added", true);
        return ResponseEntity.status(201).body(out);
    }

    @DeleteMapping("/admin/consent-scopes/{scope}")
    public ResponseEntity<Void> removeConsentScope(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("scope") String scope) {
        auth.requireAdmin(authorization);
        if (!ps.consentScopes().removeScope(scope)) {
            throw new HttpError(404, "Scope '" + scope + "' not found");
        }
        return ResponseEntity.status(204).build();
    }

    @GetMapping("/person/trusted-agent-servers")
    public List<Map<String, Object>> listTrustedAgentServers(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requireAdmin(authorization);
        return PsTrustOps.handleListTrusted(ps.trustRegistry(), settings.origin());
    }

    @PostMapping("/person/trusted-agent-servers")
    public ResponseEntity<Map<String, Object>> addTrustedAgentServer(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) byte[] raw) {
        auth.requireAdmin(authorization);
        BodyReader body = BodyReader.parse(raw);
        String issuer = body.requireString("issuer");
        String displayName = body.optString("display_name");
        TrustedAgentServer entry;
        try {
            entry = PsTrustOps.handleAddTrusted(ps.trustRegistry(), issuer, displayName);
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("issuer", entry.issuer());
        out.put("display_name", entry.displayName());
        out.put("jwks_uri", entry.jwksUri());
        out.put("jwks_fingerprint", entry.jwksFingerprint());
        out.put("added_at", entry.addedAt());
        return ResponseEntity.status(201).body(out);
    }

    @DeleteMapping("/person/trusted-agent-servers")
    public ResponseEntity<Void> removeTrustedAgentServer(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestParam("issuer") String issuer) {
        auth.requireAdmin(authorization);
        if (!ps.trustRegistry().remove(issuer)) {
            throw new HttpError(404, "issuer not in trust registry");
        }
        return ResponseEntity.status(204).build();
    }
}
