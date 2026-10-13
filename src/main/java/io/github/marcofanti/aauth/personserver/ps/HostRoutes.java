package io.github.marcofanti.aauth.personserver.ps;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Where the PS actually connects for a server identifier, like an {@code /etc/hosts} entry.
 * Draft-11 identifiers are port-less HTTPS origins; tests register
 * {@code https://as.example -> http://127.0.0.1:<port>} to reach a local fake under its real
 * identifier. Nothing is registered in production, so every URL is used as written.
 */
public final class HostRoutes {

    private static final Map<String, URI> ROUTES = new ConcurrentHashMap<>();

    private HostRoutes() {}

    /** Send requests for {@code origin} (scheme://host) to {@code target} (scheme://host:port). */
    public static void register(String origin, String target) {
        ROUTES.put(MissionUtils.stripTrailingSlash(origin), URI.create(MissionUtils.stripTrailingSlash(target)));
    }

    /** {@code url} with its origin replaced when a route is registered for it. */
    public static URI route(URI url) {
        URI target = ROUTES.get(url.getScheme() + "://" + url.getRawAuthority());
        if (target == null) {
            return url;
        }
        return URI.create(target + url.getRawPath() + (url.getRawQuery() == null ? "" : "?" + url.getRawQuery()));
    }
}
