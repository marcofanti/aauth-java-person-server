package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.personserver.web.HttpError;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Directed (pairwise) person identifiers per draft-11 §14.1: the {@code sub} a resource sees is
 * stable for that (person, resource) pair, unique within this issuer, and independent of the
 * agent and its key. Derived as HMAC-SHA256 over the pair with a per-PS secret, so two resources
 * cannot correlate the person by comparing identifiers.
 */
public final class DirectedSubjects {

    private static final int SECRET_BYTES = 32;

    private final byte[] secret;

    private DirectedSubjects(byte[] secret) {
        this.secret = secret.clone();
    }

    /** A fresh in-memory secret: identifiers change on restart (dev / tests only). */
    public static DirectedSubjects ephemeral() {
        byte[] secret = new byte[SECRET_BYTES];
        new SecureRandom().nextBytes(secret);
        return new DirectedSubjects(secret);
    }

    /** Load the secret from {@code path}, creating it on first use so identifiers survive restarts. */
    public static DirectedSubjects persistent(Path path) {
        try {
            if (Files.exists(path)) {
                byte[] secret = Base64.getDecoder()
                        .decode(Files.readString(path, StandardCharsets.UTF_8).strip());
                if (secret.length != SECRET_BYTES) {
                    throw new IllegalStateException("Directed-subject secret at " + path + " must be " + SECRET_BYTES
                            + " bytes; delete it to regenerate (all subs will change)");
                }
                return new DirectedSubjects(secret);
            }
            DirectedSubjects fresh = ephemeral();
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, Base64.getEncoder().encodeToString(fresh.secret), StandardCharsets.UTF_8);
            return fresh;
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read or write directed-subject secret " + path, e);
        }
    }

    /** The directed {@code sub} for {@code person} at {@code resource}. */
    public String subFor(String person, String resource) {
        if (person == null || resource == null) {
            throw new HttpError(400, "directed sub requires a person and a resource");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] input =
                    (person + "\u0000" + MissionUtils.stripTrailingSlash(resource)).getBytes(StandardCharsets.UTF_8);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(input));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable in this JDK", e);
        }
    }
}
