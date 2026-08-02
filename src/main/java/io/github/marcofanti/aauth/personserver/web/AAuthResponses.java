package io.github.marcofanti.aauth.personserver.web;

import io.github.marcofanti.aauth.ErrorCodes;
import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.DeferredResponse;
import io.github.marcofanti.aauth.personserver.model.InteractionTerminalResult;
import io.github.marcofanti.aauth.personserver.model.Mission;
import io.github.marcofanti.aauth.personserver.model.PendingPollOutcome;
import io.github.marcofanti.aauth.personserver.ps.web.MissionHeader;
import io.github.marcofanti.aauth.personserver.ps.web.PsEncoding;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** Response shaping shared by PS, AS, and portal routes (Python `_json_deferred` etc.). */
public final class AAuthResponses {

    private AAuthResponses() {}

    public static ResponseEntity<Map<String, Object>> aauthJsonError(int status, String error, String description) {
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(ErrorCodes.buildErrorResponse(error, description, null));
    }

    public static ResponseEntity<Object> jsonDeferred(DeferredResponse deferred) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(202)
                .header("Location", deferred.pendingUrl())
                .header("Retry-After", String.valueOf(deferred.retryAfter()))
                .header("Cache-Control", "no-store");
        String requirement = PsEncoding.buildAAuthRequirementHeader(deferred);
        if (requirement != null) {
            builder = builder.header("AAuth-Requirement", requirement);
        }
        return builder.contentType(MediaType.APPLICATION_JSON).body(PsEncoding.deferredBodyDict(deferred));
    }

    public static ResponseEntity<Object> tokenOutcomeResponse(
            io.github.marcofanti.aauth.personserver.model.TokenOutcome outcome) {
        return switch (outcome) {
            case AuthTokenResponse token -> ResponseEntity.ok(PsEncoding.authTokenHttpDict(token));
            case DeferredResponse deferred -> jsonDeferred(deferred);
        };
    }

    public static ResponseEntity<Object> tokenOutcomeResponse(PendingPollOutcome outcome) {
        return switch (outcome) {
            case AuthTokenResponse token -> ResponseEntity.ok(PsEncoding.authTokenHttpDict(token));
            case InteractionTerminalResult terminal -> ResponseEntity.ok(terminal.body());
            case DeferredResponse deferred -> jsonDeferred(deferred);
        };
    }

    public static ResponseEntity<Object> missionApprovalResponse(Mission mission) {
        return ResponseEntity.ok()
                .header(
                        "AAuth-Mission",
                        MissionHeader.buildAAuthMissionResponseHeader(mission.approver(), mission.s256()))
                .header("Cache-Control", "no-store")
                .contentType(MediaType.APPLICATION_JSON)
                .body(mission.blobBytes());
    }
}
