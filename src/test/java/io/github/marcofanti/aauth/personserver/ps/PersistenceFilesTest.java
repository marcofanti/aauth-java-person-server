package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** File-backed stores: signing key, trust registry, consent scopes, issued tokens. */
class PersistenceFilesTest {

    @TempDir
    Path tempDir;

    @Test
    void signingKeyRoundTripsThroughDisk() {
        Path keyPath = tempDir.resolve("keys/ps-signing-key.pem");
        PsSigningService first = new PsSigningService(keyPath.toString());
        assertThat(Files.exists(keyPath)).isTrue();
        assertThat(Files.exists(tempDir.resolve("keys/ps-signing-key.pem.pub"))).isTrue();

        PsSigningService second = new PsSigningService(keyPath.toString());
        assertThat(second.kid()).isEqualTo(first.kid());
        assertThat(second.keyPair().getPublic()).isEqualTo(first.keyPair().getPublic());
    }

    @Test
    void signingJwksExposesEdDsaKey() {
        PsSigningService signing = new PsSigningService(null);
        Map<String, Object> jwks = signing.getJwks();
        assertThat(jwks.get("keys")).isInstanceOf(List.class);
        Map<?, ?> jwk = (Map<?, ?>) ((List<?>) jwks.get("keys")).getFirst();
        assertThat(jwk.get("kty")).isEqualTo("OKP");
        assertThat(jwk.get("alg")).isEqualTo("Ed25519");
        assertThat(jwk.get("use")).isEqualTo("sig");
        assertThat(jwk.get("kid")).isEqualTo(signing.kid());
    }

    @Test
    void pythonWrittenKeyWithoutPubSiblingRegenerates() throws Exception {
        Path keyPath = tempDir.resolve("py-key.pem");
        Files.writeString(keyPath, "# kid:ps-python\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n");
        PsSigningService signing = new PsSigningService(keyPath.toString());
        assertThat(signing.kid()).isNotEqualTo("ps-python");
        assertThat(Files.exists(tempDir.resolve("py-key.pem.pub"))).isTrue();
    }

    @Test
    void trustRegistryPersistsAndReloads() {
        Path trustFile = tempDir.resolve("trust/ps-trusted-agents.json");
        MemoryAgentServerTrustRegistry registry = new MemoryAgentServerTrustRegistry(trustFile.toString());
        assertThat(registry.listTrusted()).isEmpty();
        assertThat(registry.isTrusted("http://portal.uma.lab")).isFalse();

        registry.add(new TrustedAgentServer(
                "http://portal.uma.lab/", "Portal", "http://portal.uma.lab/.well-known/jwks.json", "fp1", "now"));
        assertThat(registry.isTrusted("http://portal.uma.lab")).isTrue();

        MemoryAgentServerTrustRegistry reloaded = new MemoryAgentServerTrustRegistry(trustFile.toString());
        assertThat(reloaded.listTrusted()).hasSize(1);
        assertThat(reloaded.listTrusted().getFirst().issuer()).isEqualTo("http://portal.uma.lab");
        assertThat(reloaded.remove("http://portal.uma.lab")).isTrue();
        assertThat(reloaded.remove("http://portal.uma.lab")).isFalse();
    }

    @Test
    void consentScopeStoreDefaultsAndFilePersistence() {
        Path scopesFile = tempDir.resolve("consent-scopes.json");
        ConsentScopeStore store = new ConsentScopeStore(scopesFile.toString());
        assertThat(store.getScopes()).containsExactly("require:user");
        assertThat(store.requiresConsent("read require:user")).isTrue();
        assertThat(store.requiresConsent("read write")).isFalse();
        assertThat(store.requiresConsent(null)).isFalse();
        assertThat(store.requiresConsent("  ")).isFalse();

        assertThat(store.addScope("require:approval")).isTrue();
        assertThat(store.addScope("require:approval")).isFalse();
        assertThatThrownBy(() -> store.addScope("  ")).isInstanceOf(IllegalArgumentException.class);

        ConsentScopeStore reloaded = new ConsentScopeStore(scopesFile.toString());
        assertThat(reloaded.getScopes()).containsExactly("require:approval", "require:user");
        assertThat(reloaded.removeScope("require:approval")).isTrue();
        assertThat(reloaded.removeScope("require:approval")).isFalse();
    }

    @Test
    void issuedTokenStoreListsNewestFirstAndDecodesJti() {
        MemoryIssuedTokenStore store = new MemoryIssuedTokenStore();
        String payload = java.util.Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"jti\":\"abc\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String token = "eyJhbGciOiJub25lIn0." + payload + ".sig";
        store.recordIssued(new IssuedTokenStore.IssuedToken(
                token, "agent-1", "user", "http://gateway.uma.lab", "read", null, "autonomous", null));
        store.recordIssued(new IssuedTokenStore.IssuedToken(
                "opaque-token", "agent-2", "user", null, null, "why", "user_consent", java.time.Instant.EPOCH));

        List<Map<String, Object>> rows = store.listIssued();
        assertThat(rows).hasSize(2);
        assertThat(rows.getFirst()).containsEntry("agent_id", "agent-2");
        assertThat(rows.getFirst()).containsEntry("expires_at", "1970-01-01T00:00:00Z");
        assertThat(rows.getLast()).containsEntry("token_jti", "abc");
    }
}
