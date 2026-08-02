package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;

/** Builds the in-memory Person Server container ({@code build_memory_ps} in Python). */
public final class PsWiring {

    /** Wiring options; defaults mirror the Python keyword arguments. */
    public record Options(
            String publicOrigin,
            boolean autoApproveToken,
            boolean autoApproveMission,
            String agentJwtStub,
            int pendingTtlSeconds,
            String signingKeyPath,
            String trustFile,
            String consentScopesFile,
            int authTokenLifetime,
            String userId,
            boolean insecureDev,
            Supplier<Map<String, Object>> selfJwksProvider,
            Function<String, Map<String, Object>> resourceJwks,
            String missionEvaluator) {

        public static Builder builder(String publicOrigin) {
            return new Builder(publicOrigin);
        }

        public static final class Builder {
            private final String publicOrigin;
            private boolean autoApproveToken;
            private boolean autoApproveMission = true;
            private String agentJwtStub = "stub-agent-jwt";
            private int pendingTtlSeconds = 600;
            private String signingKeyPath = ".aauth/ps-signing-key.pem";
            private String trustFile = ".aauth/ps-trusted-agents.json";
            private String consentScopesFile = ".aauth/consent-scopes.json";
            private int authTokenLifetime = 3600;
            private String userId = "user";
            private boolean insecureDev;
            private Supplier<Map<String, Object>> selfJwksProvider;
            private Function<String, Map<String, Object>> resourceJwks;
            private String missionEvaluator;

            private Builder(String publicOrigin) {
                this.publicOrigin = publicOrigin;
            }

            public Builder autoApproveToken(boolean value) {
                this.autoApproveToken = value;
                return this;
            }

            public Builder autoApproveMission(boolean value) {
                this.autoApproveMission = value;
                return this;
            }

            public Builder agentJwtStub(String value) {
                this.agentJwtStub = value;
                return this;
            }

            public Builder pendingTtlSeconds(int value) {
                this.pendingTtlSeconds = value;
                return this;
            }

            public Builder signingKeyPath(String value) {
                this.signingKeyPath = value;
                return this;
            }

            public Builder trustFile(String value) {
                this.trustFile = value;
                return this;
            }

            public Builder consentScopesFile(String value) {
                this.consentScopesFile = value;
                return this;
            }

            public Builder authTokenLifetime(int value) {
                this.authTokenLifetime = value;
                return this;
            }

            public Builder userId(String value) {
                this.userId = value;
                return this;
            }

            public Builder insecureDev(boolean value) {
                this.insecureDev = value;
                return this;
            }

            public Builder selfJwksProvider(Supplier<Map<String, Object>> value) {
                this.selfJwksProvider = value;
                return this;
            }

            public Builder resourceJwks(Function<String, Map<String, Object>> value) {
                this.resourceJwks = value;
                return this;
            }

            public Builder missionEvaluator(String value) {
                this.missionEvaluator = value;
                return this;
            }

            public Options build() {
                return new Options(
                        publicOrigin,
                        autoApproveToken,
                        autoApproveMission,
                        agentJwtStub,
                        pendingTtlSeconds,
                        signingKeyPath,
                        trustFile,
                        consentScopesFile,
                        authTokenLifetime,
                        userId,
                        insecureDev,
                        selfJwksProvider,
                        resourceJwks,
                        missionEvaluator);
            }
        }
    }

    private PsWiring() {}

    /**
     * Resolve evaluator from a settings string: {@code off}/{@code none}/empty/null → no
     * Layer 1 evaluator; {@code keyword} → deterministic keyword evaluator; {@code noop} →
     * escalate everything.
     */
    public static MissionEvaluator buildEvaluator(String name) {
        if (name == null) {
            return null;
        }
        String normalized = name.strip().toLowerCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "", "off", "none" -> null;
            case "keyword" -> new KeywordMissionEvaluator();
            case "noop" -> new NoopMissionEvaluator();
            default -> throw new IllegalArgumentException("unknown mission evaluator: '" + name + "'");
        };
    }

    /** Wire in-memory stores, PS signing, trust registry, and token broker. */
    public static PsContainer buildMemoryPs(Options options) {
        PsBackend backend = new PsBackend();
        String origin = MissionUtils.stripTrailingSlash(options.publicOrigin());
        MemoryPendingStore store = new MemoryPendingStore(backend, origin, options.pendingTtlSeconds());
        FakeAsFederator federator = new FakeAsFederator();
        PsSigningService psSigning = new PsSigningService(options.signingKeyPath());
        MemoryAgentServerTrustRegistry trust = new MemoryAgentServerTrustRegistry(options.trustFile());
        ConsentScopeStore consentScopes = new ConsentScopeStore(options.consentScopesFile());
        Function<String, Map<String, Object>> resourceResolver =
                options.resourceJwks() != null ? options.resourceJwks() : new ResourceJwksResolver();
        AgentServerJwksResolver agentResolver = new AgentServerJwksResolver(origin, trust, options.selfJwksProvider());
        MemoryIssuedTokenStore issuedStore = new MemoryIssuedTokenStore();
        AuthTokenIssuer authIssuer =
                new AuthTokenIssuer(origin, psSigning, options.userId(), options.authTokenLifetime(), issuedStore);
        PsGovernance governance = new PsGovernance(backend, store);
        MemoryMissionLifecycle lifecycle =
                new MemoryMissionLifecycle(backend, store, origin, options.autoApproveMission());
        MemoryTokenBroker tokenBroker = new MemoryTokenBroker(
                store,
                federator,
                backend,
                origin,
                authIssuer,
                resourceResolver,
                consentScopes,
                options.agentJwtStub(),
                options.autoApproveToken(),
                buildEvaluator(options.missionEvaluator()));
        MemoryUserConsent consent = new MemoryUserConsent(
                backend, store, federator, authIssuer, options.agentJwtStub(), origin, resourceResolver);
        MemoryMissionControl control = new MemoryMissionControl(backend);
        return new PsContainer(
                backend,
                store,
                federator,
                lifecycle,
                tokenBroker,
                consent,
                control,
                governance,
                psSigning,
                trust,
                agentResolver,
                resourceResolver,
                authIssuer,
                issuedStore,
                consentScopes);
    }
}
