package io.github.marcofanti.aauth.personserver.portal;

import io.github.marcofanti.aauth.personserver.agentserver.AsContainer;
import io.github.marcofanti.aauth.personserver.agentserver.web.AsAuth;
import io.github.marcofanti.aauth.personserver.agentserver.web.AsConfiguration;
import io.github.marcofanti.aauth.personserver.agentserver.web.AsSettings;
import io.github.marcofanti.aauth.personserver.persistence.DbHolder;
import io.github.marcofanti.aauth.personserver.persistence.PersistedWiring;
import io.github.marcofanti.aauth.personserver.ps.DeferredAgentSelfJwks;
import io.github.marcofanti.aauth.personserver.ps.PsContainer;
import io.github.marcofanti.aauth.personserver.ps.PsWiring;
import io.github.marcofanti.aauth.personserver.ps.web.PsAuth;
import io.github.marcofanti.aauth.personserver.ps.web.PsConfiguration;
import io.github.marcofanti.aauth.personserver.ps.web.PsSettings;
import io.github.marcofanti.aauth.personserver.ps.web.PsWellKnownController.JwksDocumentSupplier;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Unified Person Portal: Person Server + Agent Server on one origin. AS issuer/origin and
 * client name align to the portal, the AS self-JWKS feeds PS agent-token verification, and
 * {@code /.well-known/jwks.json} merges both key sets (Python {@code create_portal_app}).
 */
@Configuration
@Profile({"default", "portal"})
public class PortalConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public PsSettings psSettings() {
        return PsSettings.fromEnv(System.getenv());
    }

    @Bean
    @ConditionalOnMissingBean
    public AsSettings asSettings(PsSettings psSettings) {
        return AsSettings.fromEnv(System.getenv()).withPortalAlignment(psSettings.origin(), "AAuth Person Portal");
    }

    @Bean
    public DeferredAgentSelfJwks deferredAgentSelfJwks() {
        return new DeferredAgentSelfJwks();
    }

    @Bean
    @ConditionalOnMissingBean
    public DbHolder dbHolder(PsSettings psSettings, AsSettings asSettings) {
        String url = psSettings.databaseUrl() != null ? psSettings.databaseUrl() : asSettings.databaseUrl();
        return DbHolder.fromUrl(url);
    }

    @Bean
    @ConditionalOnMissingBean
    public PsContainer psContainer(PsSettings settings, DeferredAgentSelfJwks deferredAgentSelfJwks, DbHolder db) {
        PsWiring.Options options = PsConfiguration.buildOptions(settings, deferredAgentSelfJwks);
        return db.isPresent()
                ? PersistedWiring.buildPersistedPs(db.dataSource(), options)
                : PsWiring.buildMemoryPs(options);
    }

    @Bean
    @ConditionalOnMissingBean
    public AsContainer asContainer(
            AsSettings asSettings, PsSettings psSettings, DeferredAgentSelfJwks deferredAgentSelfJwks, DbHolder db) {
        AsContainer.MemoryOptions options = AsConfiguration.buildMemoryOptions(asSettings, psSettings.origin());
        AsContainer container = db.isPresent()
                ? PersistedWiring.buildPersistedAs(db.dataSource(), options)
                : AsContainer.buildMemoryAs(options);
        deferredAgentSelfJwks.set(container.signing()::getJwks);
        return container;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwksDocumentSupplier jwksDocumentSupplier(PsContainer ps, AsContainer as) {
        return new JwksDocumentSupplier(() -> {
            List<Object> keys = new ArrayList<>();
            if (ps.psSigning().getJwks().get("keys") instanceof List<?> psKeys) {
                keys.addAll(psKeys);
            }
            if (as.signing().getJwks().get("keys") instanceof List<?> asKeys) {
                keys.addAll(asKeys);
            }
            return Map.of("keys", keys);
        });
    }

    @Bean
    @ConditionalOnMissingBean
    public PsAuth psAuth(PsSettings psSettings, PsContainer ps, AsSettings asSettings) {
        return new PsAuth(psSettings, ps, asSettings.personToken());
    }

    @Bean
    @ConditionalOnMissingBean
    public AsAuth asAuth(AsSettings asSettings, AsContainer container, PsSettings psSettings) {
        return new AsAuth(asSettings, container, psSettings.adminToken());
    }
}
