package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.model.AuthTokenResponse;
import io.github.marcofanti.aauth.personserver.model.TokenOutcome;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/** Minimal federator for demos: deterministic fake JWT-shaped strings, no HTTP to an AS. */
public final class FakeAsFederator implements AsFederator {

    @Override
    public TokenOutcome requestAuthToken(String resourceToken, String agentToken, String upstreamToken) {
        String input = resourceToken + ":" + agentToken + ":" + (upstreamToken == null ? "" : upstreamToken);
        return new AuthTokenResponse("aa-auth.fake." + sha256Hex(input).substring(0, 32), 3600);
    }

    @Override
    public TokenOutcome provideClaims(String pendingUrl, Map<String, Object> claims) {
        return new AuthTokenResponse("aa-auth.fake.claims." + claims.size(), 3600);
    }

    @Override
    public TokenOutcome pollAsPending(String pendingUrl) {
        return new AuthTokenResponse("aa-auth.fake.polled", 3600);
    }

    private static String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK is missing SHA-256", e);
        }
    }
}
