package io.github.marcofanti.aauth.personserver.web;

import static io.github.marcofanti.aauth.personserver.web.AAuthResponses.aauthJsonError;

import io.github.marcofanti.aauth.ErrorCodes;
import io.github.marcofanti.aauth.personserver.agentserver.BindingNotFoundException;
import io.github.marcofanti.aauth.personserver.agentserver.BindingRevokedException;
import io.github.marcofanti.aauth.personserver.agentserver.DuplicateStableKeyException;
import io.github.marcofanti.aauth.personserver.agentserver.InvalidSignatureException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationDeniedException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationExpiredException;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationNotFoundException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Agent Server exception → HTTP mapping, matching the FastAPI handlers. */
@RestControllerAdvice
public class AsExceptionAdvice {

    @ExceptionHandler(InvalidSignatureException.class)
    public ResponseEntity<Map<String, Object>> invalidSignature(InvalidSignatureException e) {
        return aauthJsonError(401, ErrorCodes.ERROR_INVALID_SIGNATURE, e.getMessage());
    }

    @ExceptionHandler(RegistrationNotFoundException.class)
    public ResponseEntity<Map<String, Object>> registrationNotFound(RegistrationNotFoundException e) {
        return aauthJsonError(404, ErrorCodes.ERROR_INVALID_REQUEST, e.getMessage());
    }

    @ExceptionHandler(RegistrationDeniedException.class)
    public ResponseEntity<Map<String, Object>> registrationDenied(RegistrationDeniedException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "denied");
        return ResponseEntity.status(403).body(body);
    }

    @ExceptionHandler(RegistrationExpiredException.class)
    public ResponseEntity<Map<String, Object>> registrationExpired(RegistrationExpiredException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "expired");
        return ResponseEntity.status(410).body(body);
    }

    @ExceptionHandler(BindingNotFoundException.class)
    public ResponseEntity<Map<String, Object>> bindingNotFound(BindingNotFoundException e) {
        return aauthJsonError(404, ErrorCodes.ERROR_INVALID_REQUEST, e.getMessage());
    }

    @ExceptionHandler(BindingRevokedException.class)
    public ResponseEntity<Map<String, Object>> bindingRevoked(BindingRevokedException e) {
        return aauthJsonError(401, ErrorCodes.ERROR_INVALID_REQUEST, e.getMessage());
    }

    @ExceptionHandler(DuplicateStableKeyException.class)
    public ResponseEntity<Map<String, Object>> duplicateStableKey(DuplicateStableKeyException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "conflict");
        body.put("detail", e.getMessage());
        return ResponseEntity.status(409).body(body);
    }

    @ExceptionHandler(io.github.marcofanti.aauth.personserver.agentserver.StableKeyAlreadyBoundException.class)
    public ResponseEntity<Map<String, Object>> stableKeyAlreadyBound(
            io.github.marcofanti.aauth.personserver.agentserver.StableKeyAlreadyBoundException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "conflict");
        body.put("detail", e.getMessage());
        body.put("agent_id", e.agentId());
        return ResponseEntity.status(409).body(body);
    }
}
