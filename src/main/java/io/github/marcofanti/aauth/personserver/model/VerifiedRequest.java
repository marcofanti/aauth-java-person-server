package io.github.marcofanti.aauth.personserver.model;

import java.util.Map;

/**
 * Result of HTTP signature verification. {@code scheme} is {@code "hwk"} or {@code "jkt-jwt"};
 * {@code ephemeralPub} is the JWK that signed the request; {@code stableJkt} is set only for
 * jkt-jwt ({@code urn:jkt:sha-256:<thumbprint>}).
 */
public record VerifiedRequest(String scheme, Map<String, Object> ephemeralPub, String stableJkt) {

    public VerifiedRequest(String scheme, Map<String, Object> ephemeralPub) {
        this(scheme, ephemeralPub, null);
    }
}
