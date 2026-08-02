package io.github.marcofanti.aauth.personserver.ps;

import java.util.Map;
import java.util.function.Function;

/** Wired Person Server collaborators (memory or SQL mode). */
public record PsContainer(
        MissionStatePort mission,
        PendingRequestStore pendingStore,
        AsFederator federator,
        MissionLifecycle lifecycle,
        TokenBroker tokenBroker,
        UserConsent userConsent,
        MissionControl missionControl,
        PsGovernance governance,
        PsSigningService psSigning,
        AgentServerTrustRegistry trustRegistry,
        AgentServerJwksResolver agentJwksResolver,
        Function<String, Map<String, Object>> resourceJwksResolver,
        AuthTokenIssuer authIssuer,
        IssuedTokenStore issuedTokenStore,
        ConsentScopeStore consentScopes) {}
