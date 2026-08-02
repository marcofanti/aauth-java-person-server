package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Standalone Agent Server only: original poll path {@code GET /pending/{id}} and the AS
 * JWKS at {@code /.well-known/jwks.json} (in the portal both belong to the PS side).
 */
@RestController
@Profile("agent-server")
public class AsStandaloneController {

    private final AsRegistrationController registration;
    private final AsContainer container;

    public AsStandaloneController(AsRegistrationController registration, AsContainer container) {
        this.registration = registration;
        this.container = container;
    }

    @GetMapping("/pending/{pendingId}")
    public ResponseEntity<Map<String, Object>> pollPendingStandalone(
            HttpServletRequest request, @PathVariable("pendingId") String pendingId) {
        return registration.poll(request, pendingId);
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return container.signing().getJwks();
    }
}
