package io.github.marcofanti.aauth.personserver.model;

public record PSMetadata(
        String issuer,
        String tokenEndpoint,
        String authTokenEndpoint,
        String personTokenEndpoint,
        String missionEndpoint,
        String permissionEndpoint,
        String auditEndpoint,
        String interactionEndpoint,
        String missionControlEndpoint,
        String revocationEndpoint,
        String jwksUri) {}
