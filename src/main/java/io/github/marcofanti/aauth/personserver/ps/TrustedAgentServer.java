package io.github.marcofanti.aauth.personserver.ps;

/** One trusted agent-server issuer (SPEC §Agent Token Verification). */
public record TrustedAgentServer(
        String issuer, String displayName, String jwksUri, String jwksFingerprint, String addedAt) {}
