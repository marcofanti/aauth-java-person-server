package io.github.marcofanti.aauth.personserver.persistence;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.AsSigningService;
import io.github.marcofanti.aauth.personserver.agentserver.ReplayCache;
import io.github.marcofanti.aauth.personserver.ps.AgentServerJwksResolver;
import io.github.marcofanti.aauth.personserver.ps.AsFederator;
import io.github.marcofanti.aauth.personserver.ps.AuthTokenIssuer;
import io.github.marcofanti.aauth.personserver.ps.ConsentScopeStore;
import io.github.marcofanti.aauth.personserver.ps.FakeAsFederator;
import io.github.marcofanti.aauth.personserver.ps.HttpAsFederator;
import io.github.marcofanti.aauth.personserver.ps.MemoryMissionControl;
import io.github.marcofanti.aauth.personserver.ps.MemoryMissionLifecycle;
import io.github.marcofanti.aauth.personserver.ps.MemoryTokenBroker;
import io.github.marcofanti.aauth.personserver.ps.MemoryUserConsent;
import io.github.marcofanti.aauth.personserver.ps.MissionUtils;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenIssuer;
import io.github.marcofanti.aauth.personserver.ps.PersonTokenLedger;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsSigningService;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.ResourceJwksResolver;
import io.github.marcofanti.aauth.personserver.ps.RevocationStore;
import io.github.marcofanti.aauth.personserver.ps.ServerHttp;
import io.github.marcofanti.aauth.personserver.ps.UpstreamTokens;
import java.util.Map;
import java.util.function.Function;
import javax.sql.DataSource;

/**
 * SQL-backed container wiring ({@code build_persisted_ps} / {@code build_persisted_as}):
 * the same memory brokers over SQL stores, one shared schema for PS and AS. Replay
 * protection stays in-process (DATABASE.md).
 */
public final class PersistedWiring {

    private PersistedWiring() {}

    public static PsContainer buildPersistedPs(DataSource dataSource, PsWiring.Options options) {
        String origin = MissionUtils.stripTrailingSlash(options.publicOrigin());
        SqlMissionState mission = new SqlMissionState(dataSource);
        SqlPendingStore store = new SqlPendingStore(dataSource, mission, origin, options.pendingTtlSeconds());
        PsSigningService psSigning = new PsSigningService(options.signingKeyPath());
        PersonTokenLedger personTokenLedger = new SqlPersonTokenLedger(dataSource);
        AsFederator federator = new HttpAsFederator(
                new FakeAsFederator(), ServerHttp.personServer(origin, psSigning), personTokenLedger);
        SqlTrustRegistry trust = new SqlTrustRegistry(dataSource);
        trust.importFromFileIfEmpty(options.trustFile());
        ConsentScopeStore consentScopes = new ConsentScopeStore(options.consentScopesFile());
        Function<String, Map<String, Object>> resourceResolver =
                options.resourceJwks() != null ? options.resourceJwks() : new ResourceJwksResolver();
        AgentServerJwksResolver agentResolver =
                new AgentServerJwksResolver(origin, options.selfAgentIssuer(), trust, options.selfJwksProvider());
        SqlIssuedTokenStore issuedStore = new SqlIssuedTokenStore(dataSource);
        AuthTokenIssuer authIssuer =
                new AuthTokenIssuer(origin, psSigning, options.userId(), options.authTokenLifetime(), issuedStore);
        var governance = new io.github.marcofanti.aauth.personserver.ps.PsGovernance(mission, store);
        MemoryMissionLifecycle lifecycle =
                new MemoryMissionLifecycle(mission, store, origin, options.autoApproveMission());
        RevocationStore revocations = new SqlRevocationStore(dataSource);
        UpstreamTokens upstreamTokens =
                PsWiring.upstreamTokens(origin, psSigning, personTokenLedger, issuedStore, revocations, agentResolver);
        MemoryTokenBroker tokenBroker = new MemoryTokenBroker(
                store,
                federator,
                mission,
                origin,
                authIssuer,
                resourceResolver,
                consentScopes,
                options.agentJwtStub(),
                options.autoApproveToken(),
                PsWiring.buildEvaluator(options.missionEvaluator()),
                revocations,
                upstreamTokens);
        PersonTokenIssuer personTokenIssuer = new PersonTokenIssuer(
                origin, psSigning, PsWiring.directedSubjects(options.signingKeyPath()), personTokenLedger);
        MemoryUserConsent consent = new MemoryUserConsent(
                mission,
                store,
                federator,
                authIssuer,
                options.agentJwtStub(),
                origin,
                resourceResolver,
                personTokenIssuer);
        return new PsContainer(
                mission,
                store,
                federator,
                lifecycle,
                tokenBroker,
                consent,
                new MemoryMissionControl(mission),
                governance,
                psSigning,
                trust,
                agentResolver,
                resourceResolver,
                authIssuer,
                issuedStore,
                consentScopes,
                personTokenIssuer,
                personTokenLedger,
                revocations,
                upstreamTokens);
    }

    public static AsContainer buildPersistedAs(DataSource dataSource, AsContainer.MemoryOptions options) {
        AsSigningService signing = new AsSigningService(
                options.issuer(),
                options.signingKeyPath(),
                options.previousKeyPath(),
                options.agentTokenLifetime(),
                options.psUrl());
        return new AsContainer(
                new SqlAgentServerStores.Registrations(dataSource, options.registrationTtl()),
                new SqlAgentServerStores.Bindings(dataSource),
                new ReplayCache(options.signatureWindow()),
                signing,
                AsContainer.tokenRevocation(
                        options.issuer(), signing, new SqlAgentServerStores.IssuedAgentTokens(dataSource)));
    }
}
