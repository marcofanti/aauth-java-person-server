package io.github.marcofanti.aauth.personserver.ps;

import io.github.marcofanti.aauth.signing.keys.Jwk;
import io.github.marcofanti.aauth.signing.keys.KeyPairs;
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
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the Person Server's Ed25519 signing key and exposes JWKS for aauth-person.json
 * discovery.
 *
 * <p>Persistence format: the private key is stored as PKCS#8 PEM with a {@code # kid:}
 * comment line, like the Python server. Because the JDK cannot derive an Ed25519 public key
 * from the private half, the public key is stored alongside in {@code <path>.pub} (base64
 * X.509). If the PEM exists without the {@code .pub} sibling (e.g. written by the Python
 * server), a fresh key pair is generated and both files rewritten.
 */
public final class PsSigningService {

    private static final Logger log = LoggerFactory.getLogger(PsSigningService.class);
    private static final String KID_COMMENT_PREFIX = "# kid:";

    private final KeyPair keyPair;
    private final String kid;

    public PsSigningService(String signingKeyPath) {
        if (signingKeyPath == null || signingKeyPath.isEmpty()) {
            this.keyPair = KeyPairs.generateEd25519();
            this.kid = newKid();
            log.warn("No AAUTH_PS_SIGNING_KEY_PATH — using ephemeral in-memory PS signing key; "
                    + "auth tokens will not survive restarts.");
            return;
        }
        Path path = Path.of(signingKeyPath);
        Path publicPath = Path.of(signingKeyPath + ".pub");
        if (Files.exists(path) && Files.exists(publicPath)) {
            Loaded loaded = load(path, publicPath);
            this.keyPair = loaded.keyPair();
            this.kid = loaded.kid();
            log.info("Loaded PS signing key {} from {}", kid, path);
        } else {
            if (Files.exists(path)) {
                log.warn(
                        "PS signing key {} has no {} sibling (Python-written key?); generating a new key pair",
                        path,
                        publicPath);
            }
            this.keyPair = KeyPairs.generateEd25519();
            this.kid = newKid();
            save(path, publicPath);
            log.info("Generated and saved new PS signing key {} to {}", kid, path);
        }
    }

    private record Loaded(KeyPair keyPair, String kid) {}

    private static String newKid() {
        String month = ZonedDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ofPattern("yyyyMM"));
        return "ps-" + month + "-"
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
                kid = "ps-loaded-" + path.getFileName().toString().replaceFirst("[.][^.]+$", "");
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
            throw new UncheckedIOException("failed to read PS signing key " + path, e);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Expected Ed25519 key at " + path, e);
        }
    }

    private void save(Path path, Path publicPath) {
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
            throw new UncheckedIOException("failed to write PS signing key " + path, e);
        }
    }

    public String kid() {
        return kid;
    }

    public KeyPair keyPair() {
        return keyPair;
    }

    public Map<String, Object> getJwks() {
        // Draft-10: keep the library's fully-specified alg (Ed25519); the legacy EdDSA
        // override predates RFC 9864 and is rejected by 0.2.x verification.
        Map<String, Object> jwk = new LinkedHashMap<>(Jwk.publicKeyToJwk(keyPair.getPublic(), kid));
        jwk.put("use", "sig");
        return Map.of("keys", List.of(jwk));
    }
}
