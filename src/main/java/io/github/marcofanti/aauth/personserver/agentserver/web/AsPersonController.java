package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.BindingNotFoundException;
import io.github.marcofanti.aauth.personserver.agentserver.PersonOps;
import io.github.marcofanti.aauth.personserver.agentserver.RegistrationNotFoundException;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.BodyValidationException;
import io.github.marcofanti.aauth.personserver.web.HttpError;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** Person-facing registration approval and binding management ({@code /person/*}). */
@Profile({"default", "portal", "agent-server"})
@RestController
public class AsPersonController {

    private final AsContainer container;
    private final AsAuth auth;
    private final AsSettings settings;

    public AsPersonController(AsContainer container, AsAuth auth, AsSettings settings) {
        this.container = container;
        this.auth = auth;
        this.settings = settings;
    }

    @GetMapping("/person/registrations")
    public List<Map<String, Object>> listRegistrations(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requirePerson(authorization);
        return PersonOps.handleListRegistrations(container);
    }

    @PostMapping("/person/registrations/{pendingId}/approve")
    public Map<String, Object> approveRegistration(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("pendingId") String pendingId) {
        auth.requirePerson(authorization);
        try {
            return PersonOps.handleApprove(pendingId, container, settings.serverDomain());
        } catch (RegistrationNotFoundException | IllegalArgumentException e) {
            throw new HttpError(404, e.getMessage());
        }
    }

    @PostMapping("/person/registrations/{pendingId}/deny")
    public ResponseEntity<Void> denyRegistration(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("pendingId") String pendingId) {
        auth.requirePerson(authorization);
        try {
            PersonOps.handleDeny(pendingId, container);
        } catch (RegistrationNotFoundException e) {
            throw new HttpError(404, e.getMessage());
        }
        return ResponseEntity.ok().build();
    }

    @PostMapping("/person/registrations/{pendingId}/link")
    public Map<String, Object> linkRegistration(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("pendingId") String pendingId,
            @RequestBody(required = false) byte[] raw) {
        auth.requirePerson(authorization);
        BodyReader body = BodyReader.parse(raw);
        String agentId = body.requireString("agent_id");
        try {
            return PersonOps.handleLink(pendingId, agentId, container);
        } catch (RegistrationNotFoundException | BindingNotFoundException | IllegalArgumentException e) {
            throw new HttpError(404, e.getMessage());
        }
    }

    @GetMapping("/person/bindings")
    public List<Map<String, Object>> listBindings(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requirePerson(authorization);
        return PersonOps.handleListBindings(container);
    }

    @PostMapping("/person/bindings")
    public ResponseEntity<Map<String, Object>> createBindingFromStablePub(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @RequestBody(required = false) byte[] raw) {
        auth.requirePerson(authorization);
        StringBuilder agentName = new StringBuilder();
        Map<String, Object> stablePub;
        try {
            stablePub = AsRegistrationController.parseRegisterBody(raw, agentName);
        } catch (BodyValidationException e) {
            throw new HttpError(400, e.getMessage());
        }
        Map<String, Object> result;
        try {
            result = PersonOps.handleCreateBindingFromStablePub(
                    stablePub, agentName.toString(), container, settings.serverDomain());
        } catch (IllegalArgumentException e) {
            throw new HttpError(400, e.getMessage());
        }
        return ResponseEntity.status(201).body(result);
    }

    @PostMapping("/person/bindings/{agentId}/revoke")
    public ResponseEntity<Void> revokeBinding(
            @RequestHeader(value = "Authorization", required = false) String authorization,
            @PathVariable("agentId") String agentId) {
        auth.requirePerson(authorization);
        try {
            PersonOps.handleRevokeBinding(agentId, container);
        } catch (BindingNotFoundException e) {
            throw new HttpError(404, e.getMessage());
        }
        return ResponseEntity.ok().build();
    }
}
