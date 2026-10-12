package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.ps.PersonTokenService;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.SyncHttp;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.AAuthResponses;
import io.github.marcofanti.aauth.personserver.web.BodyReader;
import io.github.marcofanti.aauth.personserver.web.BodyValidationException;
import io.github.marcofanti.aauth.personserver.web.ProblemError;
import io.github.marcofanti.aauth.personserver.web.RequestExtract;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Draft-11 {@code person_token_endpoint} (§7.1). Errors are {@code application/problem+json}. */
@Profile({"default", "portal", "ps"})
@RestController
public class PsPersonTokenController {

    private final PsAuth auth;
    private final PersonTokenService service;

    public PsPersonTokenController(PsContainer ps, PsAuth auth, PsSettings settings) {
        this.auth = auth;
        this.service = new PersonTokenService(
                new PersonTokenService.Deps(
                        ps.mission(),
                        ps.pendingStore(),
                        ps.personTokenIssuer(),
                        ps.agentJwksResolver(),
                        resource -> SyncHttp.fetchJson(resource + "/.well-known/aauth-resource.json"),
                        ps.upstreamTokens()),
                settings.userId(),
                settings.autoApproveToken());
    }

    @PostMapping("/person-token")
    public ResponseEntity<Object> postPersonToken(
            HttpServletRequest request, @RequestBody(required = false) byte[] raw) {
        SignedRequest signed = RequestExtract.signedRequest(request, raw);
        PsAuth.TokenAgentContext agent = auth.requireTokenAgent(signed);
        BodyCoverage.require(signed);
        PersonTokenService.Outcome outcome = service.request(agent, parse(raw));
        return switch (outcome) {
            case PersonTokenService.Outcome.Issued issued -> {
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("person_token", issued.token().personToken());
                body.put("expires_in", issued.token().expiresIn());
                yield ResponseEntity.ok(body);
            }
            case PersonTokenService.Outcome.Deferred deferred -> AAuthResponses.jsonDeferred(deferred.deferred());
        };
    }

    private static PersonTokenService.Params parse(byte[] raw) {
        try {
            BodyReader body = BodyReader.parse(raw);
            List<String> capabilities = null;
            List<Object> rawCapabilities = body.optList("capabilities");
            if (rawCapabilities != null) {
                capabilities = new ArrayList<>();
                for (Object value : rawCapabilities) {
                    capabilities.add(String.valueOf(value));
                }
            }
            return new PersonTokenService.Params(
                    body.optString("resource"),
                    body.optString("mission_s256"),
                    body.optString("subagent_token"),
                    body.optString("upstream_token"),
                    capabilities,
                    body.optString("tenant"),
                    body.optString("justification"));
        } catch (BodyValidationException e) {
            throw new ProblemError(400, "invalid_request", e.getMessage());
        }
    }
}
