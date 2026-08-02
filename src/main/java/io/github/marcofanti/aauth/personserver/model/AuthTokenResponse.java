package io.github.marcofanti.aauth.personserver.model;

public record AuthTokenResponse(String authToken, int expiresIn)
        implements TokenOutcome, PendingPollOutcome, PendingStoreValue {}
