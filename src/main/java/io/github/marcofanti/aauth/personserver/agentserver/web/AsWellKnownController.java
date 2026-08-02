package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.model.AgentServerMetadata;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Agent Server well-known metadata. */
@Profile({"default", "portal", "agent-server"})
@RestController
public class AsWellKnownController {

    private final AsSettings settings;

    public AsWellKnownController(AsSettings settings) {
        this.settings = settings;
    }

    @GetMapping("/.well-known/aauth-agent.json")
    public Map<String, Object> wellKnownAgent() {
        AgentServerMetadata meta = settings.metadata();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("issuer", meta.issuer());
        out.put("jwks_uri", meta.jwksUri());
        out.put("client_name", meta.clientName());
        out.put("registration_endpoint", meta.registrationEndpoint());
        out.put("refresh_endpoint", meta.refreshEndpoint());
        return out;
    }
}
