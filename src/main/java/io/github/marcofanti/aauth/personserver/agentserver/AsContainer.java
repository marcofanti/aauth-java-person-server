package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.personserver.ps.RevocationSender;
import io.github.marcofanti.aauth.personserver.ps.ServerHttp;

/** Wired Agent Server collaborators (memory or SQL mode). */
public record AsContainer(
        PendingRegistrationStore registrations,
        BindingStore bindings,
        ReplayCache replay,
        AsSigningService signing,
        AgentTokenRevocation tokenRevocation) {

    /** Revocation of this provider's agent tokens, signed as the provider ({@code aauth-agent.json}). */
    public static AgentTokenRevocation tokenRevocation(String issuer, AsSigningService signing) {
        return new AgentTokenRevocation(
                new RevocationSender(new ServerHttp(issuer, "aauth-agent.json", signing.keyPair(), signing.kid())));
    }

    /** {@code build_memory_as} in Python. */
    public record MemoryOptions(
            String issuer,
            String serverDomain,
            String signingKeyPath,
            String previousKeyPath,
            int agentTokenLifetime,
            int registrationTtl,
            int signatureWindow,
            String psUrl) {}

    public static AsContainer buildMemoryAs(MemoryOptions options) {
        AsSigningService signing = new AsSigningService(
                options.issuer(),
                options.signingKeyPath(),
                options.previousKeyPath(),
                options.agentTokenLifetime(),
                options.psUrl());
        return new AsContainer(
                new MemoryPendingRegistrationStore(options.registrationTtl()),
                new MemoryBindingStore(),
                new ReplayCache(options.signatureWindow()),
                signing,
                tokenRevocation(options.issuer(), signing));
    }
}
