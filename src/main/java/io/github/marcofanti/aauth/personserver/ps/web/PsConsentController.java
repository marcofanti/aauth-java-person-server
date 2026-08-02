package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.ConsentContext;
import io.github.marcofanti.aauth.personserver.model.DecisionResult;
import io.github.marcofanti.aauth.personserver.model.UserDecision;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** User-facing consent surface ({@code /consent}) plus the legacy {@code /interaction} aliases. */
@Profile({"default", "portal", "ps"})
@RestController
public class PsConsentController {

    private final PsContainer ps;

    public PsConsentController(PsContainer ps) {
        this.ps = ps;
    }

    private Map<String, Object> consentContext(String code, String callback) {
        ConsentContext context = ps.userConsent().getConsentContext(code);
        ps.pendingStore().setCallbackUrl(context.pendingId(), callback);
        ps.userConsent().markInteracting(context.pendingId());
        return PsEncoding.consentContextHttpDict(context);
    }

    private ResponseEntity<Map<String, Object>> decision(String pendingId, byte[] raw) {
        BodyReader body = BodyReader.parse(raw);
        UserDecision userDecision = new UserDecision(
                body.requireBoolean("approved"),
                body.optString("clarification_question"),
                body.optString("answer_text"));
        DecisionResult result = ps.userConsent().recordDecision(pendingId, userDecision);
        Map<String, Object> payload = new LinkedHashMap<>();
        if (result.redirectUrl() != null && !result.redirectUrl().isEmpty()) {
            payload.put("redirect_url", result.redirectUrl());
        }
        return ResponseEntity.ok(payload);
    }

    @GetMapping("/consent")
    public Map<String, Object> getConsent(
            @RequestParam("code") String code, @RequestParam(value = "callback", required = false) String callback) {
        return consentContext(code, callback);
    }

    @PostMapping("/consent/{pendingId}/decision")
    public ResponseEntity<Map<String, Object>> postConsentDecision(
            @PathVariable("pendingId") String pendingId, @RequestBody(required = false) byte[] raw) {
        return decision(pendingId, raw);
    }

    /** Legacy alias for GET /consent (user-facing consent context). */
    @GetMapping("/interaction")
    public Map<String, Object> getInteractionLegacy(
            @RequestParam("code") String code, @RequestParam(value = "callback", required = false) String callback) {
        return consentContext(code, callback);
    }

    /** Legacy alias for POST /consent/{pending_id}/decision. */
    @PostMapping("/interaction/{pendingId}/decision")
    public ResponseEntity<Map<String, Object>> postInteractionLegacy(
            @PathVariable("pendingId") String pendingId, @RequestBody(required = false) byte[] raw) {
        return decision(pendingId, raw);
    }
}
