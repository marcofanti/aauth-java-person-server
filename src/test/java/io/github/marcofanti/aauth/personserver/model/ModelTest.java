package io.github.marcofanti.aauth.personserver.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ModelTest {

    @Test
    void enumWireValuesMatchPython() {
        assertThat(MissionState.ACTIVE.value()).isEqualTo("active");
        assertThat(MissionState.fromValue("terminated")).isEqualTo(MissionState.TERMINATED);
        assertThat(RequirementLevel.AUTH_TOKEN.value()).isEqualTo("auth-token");
        assertThat(RequirementLevel.fromValue("clarification")).isEqualTo(RequirementLevel.CLARIFICATION);
        assertThat(PendingStatus.INTERACTING.value()).isEqualTo("interacting");
        assertThat(PendingStatus.fromValue("pending")).isEqualTo(PendingStatus.PENDING);
        assertThat(MissionLogKind.MISSION_APPROVED.value()).isEqualTo("mission_approved");
        assertThat(MissionLogKind.fromValue("token_request")).isEqualTo(MissionLogKind.TOKEN_REQUEST);
    }

    @Test
    void unknownEnumValuesAreRejected() {
        assertThatThrownBy(() -> MissionState.fromValue("nope")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RequirementLevel.fromValue("nope")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> PendingStatus.fromValue("nope")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> MissionLogKind.fromValue("nope")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void missionWithStatePreservesEverythingElse() {
        Mission mission = new Mission(
                "abc",
                new byte[] {1, 2},
                MissionState.ACTIVE,
                "aauth:agent@example",
                Instant.EPOCH,
                "user",
                "https://ps.uma.lab",
                "do things",
                List.of(Map.of("name", "WebSearch", "description", "search")),
                List.of("cap"));
        Mission terminated = mission.withState(MissionState.TERMINATED);
        assertThat(terminated.state()).isEqualTo(MissionState.TERMINATED);
        assertThat(terminated.s256()).isEqualTo("abc");
        assertThat(terminated.approvedTools()).hasSize(1);
        assertThat(terminated.capabilities()).containsExactly("cap");
    }

    @Test
    void tokenRequestBuilderDefaultsToSecureMode() {
        TokenRequest request =
                TokenRequest.builder("aauth:agent@example", "resource-token").build();
        assertThat(request.secureMode()).isTrue();
        assertThat(request.justification()).isNull();
        assertThat(request.mission()).isNull();
    }

    @Test
    void tokenRequestBuilderCarriesAllFields() {
        MissionRef ref = new MissionRef("https://ps.uma.lab", "s256hash");
        TokenRequest request = TokenRequest.builder("agent", "rt")
                .justification("why")
                .upstreamToken("up")
                .loginHint("login")
                .tenant("tenant")
                .domainHint("domain")
                .mission(ref)
                .agentCnfJwk(Map.of("kty", "OKP"))
                .agentJkt("jkt")
                .secureMode(false)
                .build();
        assertThat(request.justification()).isEqualTo("why");
        assertThat(request.upstreamToken()).isEqualTo("up");
        assertThat(request.loginHint()).isEqualTo("login");
        assertThat(request.tenant()).isEqualTo("tenant");
        assertThat(request.domainHint()).isEqualTo("domain");
        assertThat(request.mission()).isEqualTo(ref);
        assertThat(request.agentCnfJwk()).containsEntry("kty", "OKP");
        assertThat(request.agentJkt()).isEqualTo("jkt");
        assertThat(request.secureMode()).isFalse();
    }

    @Test
    void deferredResponseBuilderDefaultsAndRoundTrip() {
        DeferredResponse deferred = DeferredResponse.builder("pid", "https://ps.uma.lab/pending/pid", 5)
                .build();
        assertThat(deferred.status()).isEqualTo(PendingStatus.PENDING);
        assertThat(deferred.requirement()).isNull();

        DeferredResponse updated = deferred.toBuilder()
                .status(PendingStatus.INTERACTING)
                .requirement(RequirementLevel.APPROVAL)
                .interactionUrl("https://ps.uma.lab/consent?code=x")
                .code("x")
                .clarification("why?")
                .timeout(300)
                .options(List.of("a", "b"))
                .build();
        assertThat(updated.pendingId()).isEqualTo("pid");
        assertThat(updated.retryAfter()).isEqualTo(5);
        assertThat(updated.status()).isEqualTo(PendingStatus.INTERACTING);
        assertThat(updated.requirement()).isEqualTo(RequirementLevel.APPROVAL);
        assertThat(updated.code()).isEqualTo("x");
        assertThat(updated.clarification()).isEqualTo("why?");
        assertThat(updated.timeout()).isEqualTo(300);
        assertThat(updated.options()).containsExactly("a", "b");

        DeferredResponse copy = updated.toBuilder().build();
        assertThat(copy).isEqualTo(updated);
    }

    @Test
    void consentContextBuilderDefaults() {
        ConsentContext context = ConsentContext.builder("pid").build();
        assertThat(context.pendingId()).isEqualTo("pid");
        assertThat(context.scopes()).isEmpty();
        assertThat(context.clarificationResponses()).isEmpty();
        assertThat(context.pendingKind()).isNull();
    }

    @Test
    void consentContextBuilderCarriesPermissionFields() {
        ConsentContext context = ConsentContext.builder("pid")
                .pendingKind("token")
                .resourceName("gateway")
                .scopes(Map.of("read", "Read data"))
                .justification("because")
                .agentName("Agent")
                .clarificationResponses(List.of("answer"))
                .interactionType("question")
                .summary("done")
                .question("why?")
                .resourceIss("https://gateway.uma.lab")
                .resourceScope("read require:user")
                .resourceMissionS256("hash")
                .permissionAction("WebSearch")
                .permissionDescription("search the web")
                .permissionParameters(Map.of("q", "test"))
                .evaluatorReason("boundary case")
                .build();
        assertThat(context.pendingKind()).isEqualTo("token");
        assertThat(context.resourceScope()).isEqualTo("read require:user");
        assertThat(context.permissionAction()).isEqualTo("WebSearch");
        assertThat(context.permissionParameters()).containsEntry("q", "test");
        assertThat(context.evaluatorReason()).isEqualTo("boundary case");
    }

    @Test
    void outcomeInterfacesAllowExhaustiveSwitch() {
        TokenOutcome outcome = new AuthTokenResponse("tok", 3600);
        String result =
                switch (outcome) {
                    case AuthTokenResponse token -> token.authToken();
                    case DeferredResponse deferred -> deferred.pendingId();
                };
        assertThat(result).isEqualTo("tok");
    }

    @Test
    void permissionOutcomeFactories() {
        assertThat(PermissionOutcome.granted().permission()).isEqualTo("granted");
        assertThat(PermissionOutcome.granted().reason()).isNull();
        assertThat(PermissionOutcome.denied("no").permission()).isEqualTo("denied");
        assertThat(PermissionOutcome.denied("no").reason()).isEqualTo("no");
    }

    @Test
    void bindingWithersAreImmutable() {
        Binding binding = new Binding("aauth:x@d", "Agent", Instant.EPOCH, List.of("urn:jkt:sha-256:a"), false);
        Binding revoked = binding.withRevoked(true);
        Binding extended = binding.withAddedThumbprint("urn:jkt:sha-256:b");
        assertThat(binding.revoked()).isFalse();
        assertThat(revoked.revoked()).isTrue();
        assertThat(binding.stableKeyThumbprints()).hasSize(1);
        assertThat(extended.stableKeyThumbprints()).containsExactly("urn:jkt:sha-256:a", "urn:jkt:sha-256:b");
    }

    @Test
    void pendingRegistrationWithStatus() {
        PendingRegistration registration = new PendingRegistration(
                "id",
                Map.of("kty", "OKP"),
                Map.of("kty", "OKP"),
                "Agent",
                "urn:jkt:sha-256:x",
                Instant.EPOCH,
                Instant.EPOCH.plusSeconds(3600),
                "pending");
        assertThat(registration.withStatus("approved").status()).isEqualTo("approved");
        assertThat(registration.status()).isEqualTo("pending");
    }

    @Test
    void conveniencConstructorsMatchPythonDefaults() {
        assertThat(new MissionProposal("agent", "desc").tools()).isEmpty();
        assertThat(new MissionProposal("agent", "desc").ownerHint()).isNull();
        assertThat(new UserDecision(true).clarificationQuestion()).isNull();
        assertThat(new VerifiedRequest("hwk", Map.of()).stableJkt()).isNull();
    }
}
