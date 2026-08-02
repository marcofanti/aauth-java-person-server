package io.github.marcofanti.aauth.personserver.portal;

import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.web.PsAuth;
import java.util.List;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/** Portal-only admin routes (the standalone PS app does not expose these — Python parity). */
@Profile({"default", "portal"})
@RestController
public class PortalAdminController {

    private final PsContainer ps;
    private final PsAuth auth;

    public PortalAdminController(PsContainer ps, PsAuth auth) {
        this.ps = ps;
        this.auth = auth;
    }

    @GetMapping("/admin/issued-tokens")
    public List<Map<String, Object>> listIssuedTokens(
            @RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.requireAdmin(authorization);
        return ps.issuedTokenStore().listIssued();
    }
}
