package io.github.marcofanti.aauth.personserver.portal;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.marcofanti.aauth.personserver.agentserver.web.AsSettings;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The portal's Agent Server shares the PS origin unless one of its own is configured. */
class PortalAgentOriginTest {

    @Test
    void withoutAnAgentOriginTheAgentServerSharesThePsOrigin() {
        AsSettings settings = PortalConfiguration.portalAgentSettings(Map.of(), "https://ps.uma.lab");
        assertThat(settings.origin()).isEqualTo("https://ps.uma.lab");
        assertThat(settings.issuer()).isEqualTo("https://ps.uma.lab");
    }

    @Test
    void aConfiguredAgentOriginBecomesTheAgentServersIssuer() {
        AsSettings settings = PortalConfiguration.portalAgentSettings(
                Map.of("AAUTH_AS_PUBLIC_ORIGIN", "https://as.uma.lab/"), "https://ps.uma.lab");
        assertThat(settings.origin()).isEqualTo("https://as.uma.lab");
        assertThat(settings.issuer()).isEqualTo("https://as.uma.lab");
        assertThat(settings.metadata().issuer()).isEqualTo("https://as.uma.lab");
    }
}
