package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.persistence.DbHolder;
import io.github.marcofanti.aauth.personserver.persistence.PersistedWiring;
import io.github.marcofanti.aauth.personserver.ps.Egress;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.web.PsWellKnownController.JwksDocumentSupplier;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/** Person Server wiring from {@code AAUTH_PS_*} environment variables. */
@Configuration
@Profile("ps")
public class PsConfiguration {

    private static final Logger log = LoggerFactory.getLogger(PsConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public PsSettings psSettings() {
        return PsSettings.fromEnv(System.getenv());
    }

    @Bean
    @ConditionalOnMissingBean
    public DbHolder dbHolder(PsSettings settings) {
        return DbHolder.fromUrl(settings.databaseUrl());
    }

    @Bean
    @ConditionalOnMissingBean
    public PsContainer psContainer(PsSettings settings, DbHolder db) {
        PsWiring.Options options = buildOptions(settings, null);
        return db.isPresent()
                ? PersistedWiring.buildPersistedPs(db.dataSource(), options)
                : PsWiring.buildMemoryPs(options);
    }

    /** Shared translation of settings into wiring options (portal reuses with self JWKS). */
    public static PsWiring.Options buildOptions(
            PsSettings settings, java.util.function.Supplier<Map<String, Object>> selfJwksProvider) {
        return buildOptions(settings, selfJwksProvider, null);
    }

    /** As above, for a portal whose Agent Server has its own origin {@code selfAgentIssuer}. */
    public static PsWiring.Options buildOptions(
            PsSettings settings,
            java.util.function.Supplier<Map<String, Object>> selfJwksProvider,
            String selfAgentIssuer) {
        if (!Egress.pinningActive()) {
            log.warn("Egress DNS pinning is not active (EgressResolverProvider was not loaded); "
                    + "outbound requests are exposed to DNS rebinding");
        }
        return PsWiring.Options.builder(settings.origin())
                .autoApproveToken(settings.autoApproveToken())
                .autoApproveMission(settings.autoApproveMission())
                .agentJwtStub(settings.agentJwtStub())
                .pendingTtlSeconds(settings.pendingTtlSeconds())
                .signingKeyPath(settings.signingKeyPath())
                .trustFile(settings.trustFile())
                .consentScopesFile(settings.consentScopesFile())
                .authTokenLifetime(settings.authTokenLifetime())
                .userId(settings.userId())
                .insecureDev(settings.insecureDev())
                .selfJwksProvider(selfJwksProvider)
                .missionEvaluator(settings.missionEvaluator())
                .missionLifetimeSeconds(settings.missionLifetimeSeconds())
                .selfAgentIssuer(selfAgentIssuer)
                .build();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwksDocumentSupplier jwksDocumentSupplier(PsContainer ps) {
        return new JwksDocumentSupplier(() -> ps.psSigning().getJwks());
    }

    @Bean
    @ConditionalOnMissingBean
    public PsAuth psAuth(PsSettings settings, PsContainer ps) {
        return new PsAuth(settings, ps);
    }
}
