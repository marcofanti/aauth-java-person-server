package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.HttpSigVerifier;
import io.github.marcofanti.aauth.personserver.model.VerifiedRequest;
import io.github.marcofanti.aauth.personserver.ps.web.HttpSigAuth.SignedRequest;
import io.github.marcofanti.aauth.personserver.web.HttpError;

/** Agent Server authentication: HTTP message signatures + person bearer token. */
public final class AsAuth {

    private final AsSettings settings;
    private final HttpSigVerifier verifier;
    private final String portalAdminToken;

    public AsAuth(AsSettings settings, AsContainer container) {
        this(settings, container, null);
    }

    /** Portal mode: the PS admin token is also accepted on {@code /person/*} routes. */
    public AsAuth(AsSettings settings, AsContainer container, String portalAdminToken) {
        this.settings = settings;
        this.verifier = new HttpSigVerifier(container.replay(), settings.insecureDev());
        this.portalAdminToken = portalAdminToken;
    }

    /** Verify HTTP Message Signature on agent-facing requests (401 on failure). */
    public VerifiedRequest requireHttpSig(SignedRequest request) {
        return verifier.verify(request);
    }

    /** Validate {@code Authorization: Bearer <person_token>} for {@code /person/*} endpoints. */
    public void requirePerson(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new HttpError(401, "Authorization: Bearer required");
        }
        String got = authorization.substring("Bearer ".length()).strip();
        if (got.equals(settings.personToken())) {
            return;
        }
        if (portalAdminToken != null && got.equals(portalAdminToken)) {
            return;
        }
        throw new HttpError(403, "Invalid person token");
    }
}
