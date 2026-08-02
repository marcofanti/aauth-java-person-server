package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.model.PSMetadata;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Well-known metadata + JWKS. The JWKS payload comes from a supplier bean so the unified
 * portal can merge Person Server and Agent Server keys at the same path.
 */
@Profile({"default", "portal", "ps"})
@RestController
public class PsWellKnownController {

    /** Bean supplying the payload for {@code /.well-known/jwks.json}. */
    public record JwksDocumentSupplier(Supplier<Map<String, Object>> supplier) {}

    private final PsSettings settings;
    private final JwksDocumentSupplier jwksSupplier;

    public PsWellKnownController(PsSettings settings, JwksDocumentSupplier jwksSupplier) {
        this.settings = settings;
        this.jwksSupplier = jwksSupplier;
    }

    @GetMapping("/.well-known/aauth-person.json")
    public Map<String, Object> wellKnownPerson() {
        PSMetadata meta = settings.metadata();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("issuer", meta.issuer());
        out.put("token_endpoint", meta.tokenEndpoint());
        out.put("mission_endpoint", meta.missionEndpoint());
        out.put("permission_endpoint", meta.permissionEndpoint());
        out.put("audit_endpoint", meta.auditEndpoint());
        out.put("interaction_endpoint", meta.interactionEndpoint());
        out.put("mission_control_endpoint", meta.missionControlEndpoint());
        out.put("jwks_uri", meta.jwksUri());
        return out;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return jwksSupplier.supplier().get();
    }
}
