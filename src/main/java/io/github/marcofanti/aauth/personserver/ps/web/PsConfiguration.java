package io.github.marcofanti.aauth.personserver.ps.web;

import io.github.marcofanti.aauth.personserver.persistence.DbHolder;
import io.github.marcofanti.aauth.personserver.persistence.PersistedWiring;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.web.PsWellKnownController.JwksDocumentSupplier;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/** Person Server wiring from {@code AAUTH_PS_*} environment variables. */
@Configuration
@Profile("ps")
public class PsConfiguration {

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
