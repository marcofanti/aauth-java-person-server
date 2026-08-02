package io.github.marcofanti.aauth.personserver.model;

public record AgentServerMetadata(
        String issuer, String jwksUri, String clientName, String registrationEndpoint, String refreshEndpoint) {}
