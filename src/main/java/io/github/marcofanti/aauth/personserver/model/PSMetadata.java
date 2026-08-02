package io.github.marcofanti.aauth.personserver.model;

public record PSMetadata(
        String issuer,
        String tokenEndpoint,
        String missionEndpoint,
        String permissionEndpoint,
        String auditEndpoint,
        String interactionEndpoint,
        String missionControlEndpoint,
        String jwksUri) {}
