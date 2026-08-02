package io.github.marcofanti.aauth.personserver.agentserver.web;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.persistence.DbHolder;
import io.github.marcofanti.aauth.personserver.persistence.PersistedWiring;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/** Agent Server wiring from {@code AAUTH_AS_*} environment variables. */
@Configuration
@Profile("agent-server")
public class AsConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AsSettings asSettings() {
        return AsSettings.fromEnv(System.getenv());
    }

    @Bean
    @ConditionalOnMissingBean
    public DbHolder dbHolder(AsSettings settings) {
        return DbHolder.fromUrl(settings.databaseUrl());
    }

    @Bean
    @ConditionalOnMissingBean
    public AsContainer asContainer(AsSettings settings, DbHolder db) {
        AsContainer.MemoryOptions options = buildMemoryOptions(settings, null);
        return db.isPresent()
                ? PersistedWiring.buildPersistedAs(db.dataSource(), options)
                : AsContainer.buildMemoryAs(options);
    }

    /** Shared translation of settings into wiring options (portal passes the PS url). */
    public static AsContainer.MemoryOptions buildMemoryOptions(AsSettings settings, String psUrl) {
        return new AsContainer.MemoryOptions(
                settings.issuer(),
                settings.serverDomain(),
                settings.signingKeyPath(),
                settings.previousKeyPath(),
                settings.agentTokenLifetime(),
                settings.registrationTtl(),
                settings.signatureWindow(),
                psUrl);
    }

    @Bean
    @ConditionalOnMissingBean
    public AsAuth asAuth(AsSettings settings, AsContainer container) {
        return new AsAuth(settings, container);
    }
}
