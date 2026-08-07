package io.github.marcofanti.aauth.personserver.agentserver;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
import io.github.marcofanti.aauth.tokens.AgentTokens;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the agent server's Ed25519 signing key and issues agent tokens. Key files use the
 * same layout as {@code PsSigningService}: kid-comment PEM plus a {@code .pub} sibling.
 */
public final class AsSigningService {

    private static final Logger log = LoggerFactory.getLogger(AsSigningService.class);
    private static final String KID_COMMENT_PREFIX = "# kid:";

    private final String issuer;
    private final int lifetimeSeconds;
    private final String psUrl;
    private final KeyPair keyPair;
    private final String kid;
    private KeyPair previousKey;
    private String previousKid;

    public AsSigningService(
            String issuer, String signingKeyPath, String previousKeyPath, int agentTokenLifetime, String psUrl) {
        this.issuer = issuer;
        this.lifetimeSeconds = agentTokenLifetime;
        this.psUrl = psUrl;

        if (signingKeyPath == null || signingKeyPath.isEmpty()) {
            this.keyPair = KeyPairs.generateEd25519();
            this.kid = newKid();
            log.warn("No signing_key_path configured — using ephemeral in-memory key. "
                    + "Tokens will not survive restarts.");
        } else {
            Path path = Path.of(signingKeyPath);
            Path publicPath = Path.of(signingKeyPath + ".pub");
            if (Files.exists(path) && Files.exists(publicPath)) {
                Loaded loaded = load(path, publicPath);
                this.keyPair = loaded.keyPair();
                this.kid = loaded.kid();
                log.info("Loaded signing key {} from {}", kid, path);
            } else {
                this.keyPair = KeyPairs.generateEd25519();
                this.kid = newKid();
                save(keyPair, kid, path, publicPath);
                log.info("Generated and saved new signing key {} to {}", kid, path);
            }
        }
        if (previousKeyPath != null && !previousKeyPath.isEmpty()) {
            Path path = Path.of(previousKeyPath);
            Path publicPath = Path.of(previousKeyPath + ".pub");
            if (Files.exists(path) && Files.exists(publicPath)) {
                Loaded loaded = load(path, publicPath);
                this.previousKey = loaded.keyPair();
                this.previousKid = loaded.kid();
            }
        }
    }

    private record Loaded(KeyPair keyPair, String kid) {}

    private static String newKid() {
        String month = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMM"));
        return "as-" + month + "-"
                + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
    }

    private static Loaded load(Path path, Path publicPath) {
        try {
            List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
            String kid = null;
            StringBuilder base64 = new StringBuilder();
            for (String line : lines) {
                if (line.startsWith(KID_COMMENT_PREFIX)) {
                    kid = line.substring(KID_COMMENT_PREFIX.length()).strip();
                } else if (!line.startsWith("-----") && !line.isBlank()) {
                    base64.append(line.strip());
                }
            }
            if (kid == null) {
                kid = "as-loaded-" + path.getFileName().toString().replaceFirst("[.][^.]+$", "");
            }
            byte[] privateBytes = Base64.getMimeDecoder().decode(base64.toString());
            byte[] publicBytes = Base64.getDecoder()
                    .decode(Files.readString(publicPath, StandardCharsets.UTF_8).strip());
            KeyFactory factory = KeyFactory.getInstance("Ed25519");
            KeyPair pair = new KeyPair(
                    factory.generatePublic(new X509EncodedKeySpec(publicBytes)),
                    factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes)));
            return new Loaded(pair, kid);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read signing key " + path, e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Expected Ed25519 key at " + path, e);
        }
    }

    private static void save(KeyPair keyPair, String kid, Path path, Path publicPath) {
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                    .encodeToString(keyPair.getPrivate().getEncoded());
            String pem = KID_COMMENT_PREFIX + kid + "\n-----BEGIN PRIVATE KEY-----\n"
                    + body
                    + "\n-----END PRIVATE KEY-----\n";
            Files.writeString(path, pem, StandardCharsets.UTF_8);
            Files.writeString(
                    publicPath,
                    Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                    StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to write signing key " + path, e);
        }
    }

    public String kid() {
        return kid;
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    /** JWKS with current + previous signing public keys. */
    public Map<String, Object> getJwks() {
        List<Map<String, Object>> keys = new ArrayList<>();
        keys.add(toJwk(keyPair, kid));
        if (previousKey != null) {
            keys.add(toJwk(previousKey, previousKid == null ? "prev" : previousKid));
        }
        return Map.of("keys", keys);
    }

    /** Create and sign an {@code aa-agent+jwt}. */
    public String createAgentToken(String agentId, Map<String, Object> ephemeralPub, Integer lifetimeSeconds) {
        int lifetime = lifetimeSeconds != null ? lifetimeSeconds : this.lifetimeSeconds;
        long exp = Instant.now().getEpochSecond() + lifetime;
        AgentTokens.Spec.Builder builder = AgentTokens.Spec.builder(
                        issuer, agentId, ephemeralPub, keyPair.getPrivate(), kid)
                .exp(exp);
        // Always emitted: library >= 0.2.2 verifies ps as a well-formed http(s) server URL
        // (HTTPS-in-production is deployment policy), so dev origins verify too.
        if (psUrl != null && !psUrl.isEmpty()) {
            builder.ps(psUrl);
        }
        return AgentTokens.create(builder.build());
    }

    private static Map<String, Object> toJwk(KeyPair keyPair, String kid) {
        // Draft-10: keep the library's fully-specified alg (Ed25519), not legacy EdDSA.
        Map<String, Object> jwk = new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), kid));
        jwk.put("use", "sig");
        return jwk;
    }
}
