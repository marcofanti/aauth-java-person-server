package io.github.marcofanti.aauth.personserver.web;

import static io.github.marcofanti.aauth.personserver.web.AAuthResponses.aauthJsonError;

import io.github.marcofanti.aauth.ErrorCodes;
import io.github.marcofanti.aauth.headers.AAuthHeaders;
import io.github.marcofanti.aauth.personserver.ps.AgentTokenRejectException;
import io.github.marcofanti.aauth.personserver.ps.ClarificationLimitException;
import io.github.marcofanti.aauth.personserver.ps.ForbiddenOwnerException;
import io.github.marcofanti.aauth.personserver.ps.InvalidInteractionCodeException;
import io.github.marcofanti.aauth.personserver.ps.MissionDeniedException;
import io.github.marcofanti.aauth.personserver.ps.MissionTerminatedException;
import io.github.marcofanti.aauth.personserver.ps.NotFoundException;
import io.github.marcofanti.aauth.personserver.ps.PendingDeniedException;
import io.github.marcofanti.aauth.personserver.ps.PendingExpiredException;
import io.github.marcofanti.aauth.personserver.ps.PendingGoneException;
import io.github.marcofanti.aauth.personserver.ps.ResourceTokenRejectException;
import io.github.marcofanti.aauth.personserver.ps.SlowDownException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Person Server exception → HTTP mapping, byte-compatible with the FastAPI handlers. */
@RestControllerAdvice
public class PsExceptionAdvice {

    static boolean isAgentProtocolPath(String path) {
        return path.startsWith("/mission")
                || path.startsWith("/token")
                || path.startsWith("/pending")
                || path.startsWith("/permission")
                || path.startsWith("/audit")
                || path.equals("/interaction")
                || path.startsWith("/register")
                || path.startsWith("/refresh")
                // Agent Server person routes use AAuth-shaped 401/400 bodies (Python AS app).
                || path.startsWith("/person/registrations")
                || path.startsWith("/person/bindings");
    }

    @ExceptionHandler(MissionTerminatedException.class)
    public ResponseEntity<Map<String, Object>> missionTerminated(MissionTerminatedException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "mission_terminated");
        body.put("mission_status", "terminated");
        return ResponseEntity.status(403).body(body);
    }

    @ExceptionHandler(MissionDeniedException.class)
    public ResponseEntity<Map<String, Object>> missionDenied(MissionDeniedException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "mission_denied");
        body.put("error_description", e.reason());
        return ResponseEntity.status(403).body(body);
    }

    @ExceptionHandler(InvalidInteractionCodeException.class)
    public ResponseEntity<Map<String, Object>> invalidCode(InvalidInteractionCodeException e) {
        return aauthJsonError(
                410, ErrorCodes.ERROR_INVALID_CODE, "interaction code not recognized or already consumed");
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<Map<String, Object>> notFound(NotFoundException e) {
        String message = e.getMessage() == null || e.getMessage().isEmpty() ? "not found" : e.getMessage();
        return aauthJsonError(404, ErrorCodes.ERROR_INVALID_REQUEST, message);
    }

    @ExceptionHandler(PendingGoneException.class)
    public ResponseEntity<Map<String, Object>> gone(PendingGoneException e) {
        return aauthJsonError(410, ErrorCodes.ERROR_INVALID_CODE, "pending request was cancelled");
    }

    @ExceptionHandler(PendingDeniedException.class)
    public ResponseEntity<Map<String, Object>> denied(PendingDeniedException e) {
        String reason = e.reason();
        if ("abandoned".equals(reason)) {
            return aauthJsonError(403, ErrorCodes.ERROR_ABANDONED, "user did not complete interaction");
        }
        if ("denied".equals(reason)) {
            return aauthJsonError(403, ErrorCodes.ERROR_DENIED, "request was denied");
        }
        return aauthJsonError(403, ErrorCodes.ERROR_DENIED, reason);
    }

    @ExceptionHandler(PendingExpiredException.class)
    public ResponseEntity<Map<String, Object>> expired(PendingExpiredException e) {
        return aauthJsonError(408, ErrorCodes.ERROR_EXPIRED, "pending request expired");
    }

    @ExceptionHandler(SlowDownException.class)
    public ResponseEntity<Map<String, Object>> slowDown(SlowDownException e) {
        return aauthJsonError(429, ErrorCodes.ERROR_SLOW_DOWN, "polling too frequently");
    }

    @ExceptionHandler(ClarificationLimitException.class)
    public ResponseEntity<Map<String, Object>> clarificationLimit(ClarificationLimitException e) {
        return aauthJsonError(400, ErrorCodes.ERROR_INVALID_REQUEST, "clarification round limit exceeded");
    }

    @ExceptionHandler(ForbiddenOwnerException.class)
    public ResponseEntity<Map<String, Object>> forbiddenOwner(ForbiddenOwnerException e) {
        return aauthJsonError(403, ErrorCodes.ERROR_DENIED, "not owner of this mission");
    }

    @ExceptionHandler(ResourceTokenRejectException.class)
    public ResponseEntity<Map<String, Object>> resourceTokenReject(ResourceTokenRejectException e) {
        return aauthJsonError(401, e.error(), e.getMessage());
    }

    @ExceptionHandler(AgentTokenRejectException.class)
    public ResponseEntity<Map<String, Object>> agentTokenReject(AgentTokenRejectException e) {
        return aauthJsonError(401, e.error(), e.getMessage());
    }

    @ExceptionHandler(BodyValidationException.class)
    public ResponseEntity<Map<String, Object>> validation(BodyValidationException e, HttpServletRequest request) {
        if (isAgentProtocolPath(request.getRequestURI())) {
            return aauthJsonError(400, ErrorCodes.ERROR_INVALID_REQUEST, e.getMessage());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("detail", e.getMessage());
        return ResponseEntity.status(422).body(body);
    }

    @ExceptionHandler(UnsupportedSchemeError.class)
    public ResponseEntity<Map<String, Object>> unsupportedScheme(UnsupportedSchemeError e) {
        // Draft-10 posture: tell the agent what this server accepts so it can renegotiate.
        ResponseEntity<Map<String, Object>> base = aauthJsonError(401, ErrorCodes.ERROR_UNSUPPORTED_SCHEME, e.detail());
        return ResponseEntity.status(401)
                .header(AAuthHeaders.HEADER_SIGNATURE_ERROR, "error=" + ErrorCodes.ERROR_UNSUPPORTED_SCHEME)
                .header(
                        AAuthHeaders.HEADER_ACCEPT_SIGNATURE_SCHEME,
                        AAuthHeaders.buildAcceptListHeader(List.of("hwk", "jwt")))
                .header(
                        AAuthHeaders.HEADER_ACCEPT_SIGNATURE_ALG,
                        AAuthHeaders.buildAcceptListHeader(List.of("Ed25519")))
                .body(base.getBody());
    }

    @ExceptionHandler(HttpError.class)
    public ResponseEntity<Map<String, Object>> httpError(HttpError e, HttpServletRequest request) {
        if (e.status() == 401 && isAgentProtocolPath(request.getRequestURI())) {
            return aauthJsonError(401, ErrorCodes.ERROR_INVALID_SIGNATURE, e.detail());
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("detail", e.detail());
        return ResponseEntity.status(e.status()).body(body);
    }
}
