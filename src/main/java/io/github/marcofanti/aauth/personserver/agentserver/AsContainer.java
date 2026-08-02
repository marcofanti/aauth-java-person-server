package io.github.marcofanti.aauth.personserver.agentserver;

/** Wired Agent Server collaborators (memory or SQL mode). */
public record AsContainer(
        PendingRegistrationStore registrations, BindingStore bindings, ReplayCache replay, AsSigningService signing) {

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
                signing);
    }
}
