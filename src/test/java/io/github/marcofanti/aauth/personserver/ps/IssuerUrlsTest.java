package io.github.marcofanti.aauth.personserver.ps;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class IssuerUrlsTest {

    @Test
    void normalizeIssuerStripsTrailingSlash() {
        assertThat(IssuerUrls.normalizeIssuer("http://a.example/")).isEqualTo("http://a.example");
        assertThat(IssuerUrls.normalizeIssuer("http://a.example")).isEqualTo("http://a.example");
    }

    @Test
    void normalizeAudClaimHandlesStringsAndLists() {
        assertThat(IssuerUrls.normalizeAudClaim(null)).isEmpty();
        assertThat(IssuerUrls.normalizeAudClaim(List.of())).isEmpty();
        assertThat(IssuerUrls.normalizeAudClaim("http://a.example/")).isEqualTo("http://a.example");
        assertThat(IssuerUrls.normalizeAudClaim(List.of("http://a.example/", "ignored")))
                .isEqualTo("http://a.example");
    }

    @Test
    void equivalenceNormalizesLocalhostSchemeAndPorts() {
        assertThat(IssuerUrls.issuerUrlsEquivalent("http://localhost:8765", "http://127.0.0.1:8765"))
                .isTrue();
        assertThat(IssuerUrls.issuerUrlsEquivalent("http://a.example", "http://a.example:80"))
                .isTrue();
        assertThat(IssuerUrls.issuerUrlsEquivalent("https://a.example", "https://a.example:443"))
                .isTrue();
        assertThat(IssuerUrls.issuerUrlsEquivalent("HTTP://A.EXAMPLE", "http://a.example"))
                .isTrue();
        assertThat(IssuerUrls.issuerUrlsEquivalent("http://a.example", "https://a.example"))
                .isFalse();
        assertThat(IssuerUrls.issuerUrlsEquivalent("http://a.example", "http://b.example"))
                .isFalse();
        assertThat(IssuerUrls.issuerUrlsEquivalent("", "http://a.example")).isFalse();
        assertThat(IssuerUrls.issuerUrlsEquivalent(null, "http://a.example")).isFalse();
    }
}
