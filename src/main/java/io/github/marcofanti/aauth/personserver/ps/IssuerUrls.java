package io.github.marcofanti.aauth.personserver.ps;

import java.net.URI;
import java.util.List;
import java.util.Locale;

/** Issuer / audience URL normalization (SPEC §Agent Token Verification). */
public final class IssuerUrls {

    private IssuerUrls() {}

    public static String normalizeIssuer(String url) {
        return MissionUtils.stripTrailingSlash(url);
    }

    /** Single string {@code aud} value from JWT claims ({@code aud} may be a string or list). */
    public static String normalizeAudClaim(Object raw) {
        Object value = raw;
        if (value == null) {
            return "";
        }
        if (value instanceof List<?> list) {
            if (list.isEmpty()) {
                return "";
            }
            value = list.getFirst();
        }
        return normalizeIssuer(String.valueOf(value).strip());
    }

    /**
     * True if {@code a} and {@code b} denote the same logical HTTP origin (scheme, host,
     * port). Handles {@code localhost} vs {@code 127.0.0.1}.
     */
    public static boolean issuerUrlsEquivalent(String a, String b) {
        if (a == null || b == null || a.isEmpty() || b.isEmpty()) {
            return false;
        }
        return originTuple(a).equals(originTuple(b));
    }

    private static String originTuple(String url) {
        String u = normalizeIssuer(url.strip());
        if (!u.contains("://")) {
            u = "http://" + u;
        }
        URI parsed = URI.create(u);
        String scheme = parsed.getScheme() == null ? "http" : parsed.getScheme().toLowerCase(Locale.ROOT);
        String host = parsed.getHost() == null ? "" : parsed.getHost().toLowerCase(Locale.ROOT);
        if (host.equals("localhost") || host.equals("::1") || host.equals("[::1]")) {
            host = "127.0.0.1";
        }
        int port = parsed.getPort();
        if (port == -1) {
            port = scheme.equals("https") ? 443 : 80;
        }
        return scheme + "|" + host + "|" + port;
    }
}
