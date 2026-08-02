package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.PyIso;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationOps;
import io.github.marcofanti.aauth.personserver.model.VerifiedRequest;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.BodyValidationException;
import io.github.marcofanti.aauth.personserver.web.RequestExtract;
import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Agent-facing registration + refresh. Polling lives at {@code /register/pending/{id}} on
 * the portal and {@code /pending/{id}} on the standalone Agent Server (the PS owns
 * {@code /pending/{id}} for consent flows); both mappings dispatch to the same logic.
 */
@Profile({"default", "portal", "agent-server"})
@RestController
public class AsRegistrationController {

    private final AsContainer container;
    private final AsAuth auth;
    private final boolean standaloneAgentServer;

    public AsRegistrationController(AsContainer container, AsAuth auth, Environment environment) {
        this.container = container;
        this.auth = auth;
        this.standaloneAgentServer = environment.matchesProfiles("agent-server");
    }

    /** Parse + validate {@code {stable_pub, agent_name}} (RegisterBody parity). */
    static Map<String, Object> parseRegisterBody(byte[] raw, StringBuilder agentNameOut) {
        BodyReader body = BodyReader.parse(raw);
        Map<String, Object> stablePub = body.optMap("stable_pub");
        if (stablePub == null) {
            throw new BodyValidationException("field 'stable_pub' required");
        }
        String agentName = body.optString("agent_name");
        agentName = agentName == null ? "" : agentName.strip();
        if (agentName.isEmpty()) {
            throw new BodyValidationException("agent_name must be non-empty and not only whitespace");
        }
        if (agentName.length() > 256) {
            throw new BodyValidationException("agent_name must be at most 256 characters after trimming");
        }
        agentNameOut.append(agentName);
        return stablePub;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> postRegister(
            HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        VerifiedRequest verified = auth.requireHttpSig(RequestExtract.signedRequest(request, raw));
        StringBuilder agentName = new StringBuilder();
        Map<String, Object> stablePub = parseRegisterBody(raw, agentName);
        RegistrationOps.RegisterResult result =
                RegistrationOps.handleRegister(verified, stablePub, agentName.toString(), container);
        return switch (result) {
            case RegistrationOps.RegisterResult.Immediate immediate -> {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("agent_token", immediate.agentToken());
                yield ResponseEntity.ok(body);
            }
            case RegistrationOps.RegisterResult.Pending pending -> {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "pending");
                body.put("expires_at", PyIso.format(pending.expiresAt()));
                String pollPath = (standaloneAgentServer ? "/pending/" : "/register/pending/") + pending.pendingId();
                yield ResponseEntity.status(202)
                        .header("Location", pollPath)
                        .header("Retry-After", "5")
                        .header("Cache-Control", "no-store")
                        .body(body);
            }
        };
    }

    @GetMapping("/register/pending/{pendingId}")
    public ResponseEntity<Map<String, Object>> pollPendingPortal(
            HttpServletRequest request, @PathVariable("pendingId") String pendingId) {
        return poll(request, pendingId);
    }

    ResponseEntity<Map<String, Object>> poll(HttpServletRequest request, String pendingId) {
        VerifiedRequest verified = auth.requireHttpSig(RequestExtract.signedRequest(request, null));
        RegistrationOps.PollResult result = RegistrationOps.handlePollPending(pendingId, verified, container);
        return switch (result) {
            case RegistrationOps.PollResult.Token token -> {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("agent_token", token.agentToken());
                yield ResponseEntity.ok(body);
            }
            case RegistrationOps.PollResult.StillPending pending -> {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", "pending");
                yield ResponseEntity.status(202)
                        .header("Retry-After", "5")
                        .header("Cache-Control", "no-store")
                        .body(body);
            }
        };
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> postRefresh(
            HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        VerifiedRequest verified = auth.requireHttpSig(RequestExtract.signedRequest(request, raw));
        String token = RegistrationOps.handleRefresh(verified, container);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent_token", token);
        return ResponseEntity.ok(body);
    }
}
