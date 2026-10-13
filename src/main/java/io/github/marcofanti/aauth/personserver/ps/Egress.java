package io.github.marcofanti.aauth.personserver.ps;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.stream.Collectors;

/**
 * The single gate for the PS's outbound HTTP. Agents and resources choose many of the URLs the
 * PS fetches (a resource's {@code iss}, a four-party {@code aud}, a person-token
 * {@code resource}), so every request must be HTTPS to a host that does not resolve to a
 * loopback, private, link-local, CGNAT or unique-local address. Hosts in
 * {@code AAUTH_PS_EGRESS_ALLOW_HOSTS} (comma-separated, {@code *.suffix} wildcards) skip the
 * address check, e.g. {@code *.uma.lab} for the local HTTPS setup. Responses are capped at
 * {@link #MAX_BODY_BYTES}.
 *
 * <p>The check resolves the host before the HTTP client resolves it again, so a DNS answer
 * that changes in between (rebinding) is not covered; deployments should also restrict egress
 * at the network layer.
 */
public final class Egress {

    /** Largest response body the PS reads from a peer. */
    public static final int MAX_BODY_BYTES = 1 << 20;

    private static volatile Set<String> allowedHosts = parse(System.getenv("AAUTH_PS_EGRESS_ALLOW_HOSTS"));

    private Egress() {}

    /** Replace the allow-list (patterns as in {@code AAUTH_PS_EGRESS_ALLOW_HOSTS}). */
    public static void allowHosts(String patterns) {
        allowedHosts = parse(patterns);
    }

    private static Set<String> parse(String patterns) {
        if (patterns == null || patterns.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(patterns.split(","))
                .map(pattern -> pattern.strip().toLowerCase(Locale.ROOT))
                .filter(pattern -> !pattern.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * The address to connect to for {@code url}, after the egress checks.
     *
     * @throws IllegalArgumentException when the URL is not HTTPS, does not resolve, or resolves
     *     to an internal address that is not allow-listed
     */
    public static URI target(String url) {
        URI uri = URI.create(url);
        URI routed = HostRoutes.route(uri);
        if (!routed.equals(uri)) {
            return routed;
        }
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException("egress refused: only https URLs are fetched, not " + url);
        }
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        if (isAllowListed(host)) {
            return uri;
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("egress refused: cannot resolve " + host, e);
        }
        for (InetAddress address : addresses) {
            if (isInternal(address)) {
                throw new IllegalArgumentException("egress refused: " + host + " resolves to internal address "
                        + address.getHostAddress() + "; allow it with AAUTH_PS_EGRESS_ALLOW_HOSTS");
            }
        }
        return uri;
    }

    private static boolean isAllowListed(String host) {
        for (String pattern : allowedHosts) {
            if (pattern.equals(host) || (pattern.startsWith("*.") && host.endsWith(pattern.substring(1)))) {
                return true;
            }
        }
        return false;
    }

    static boolean isInternal(InetAddress address) {
        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            // 100.64.0.0/10 (CGNAT) and 0.0.0.0/8.
            return (bytes[0] == 100 && (bytes[1] & 0xC0) == 64) || bytes[0] == 0;
        }
        if (address instanceof Inet6Address) {
            // fc00::/7 (unique local) and IPv4-mapped ::ffff:a.b.c.d.
            if ((bytes[0] & 0xFE) == 0xFC) {
                return true;
            }
            if (isIpv4Mapped(bytes)) {
                try {
                    return isInternal(InetAddress.getByAddress(Arrays.copyOfRange(bytes, 12, 16)));
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isIpv4Mapped(byte[] bytes) {
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }

    /** A response body handler that fails once the body exceeds {@link #MAX_BODY_BYTES}. */
    public static HttpResponse.BodyHandler<String> cappedBody() {
        return responseInfo -> new CappedBody();
    }

    private static final class CappedBody implements HttpResponse.BodySubscriber<String> {

        private final CompletableFuture<String> result = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        @Override
        public CompletionStage<String> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription newSubscription) {
            subscription = newSubscription;
            newSubscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            for (ByteBuffer item : items) {
                if (buffer.size() + item.remaining() > MAX_BODY_BYTES) {
                    subscription.cancel();
                    result.completeExceptionally(new IOException("response body exceeds " + MAX_BODY_BYTES + " bytes"));
                    return;
                }
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                buffer.write(chunk, 0, chunk.length);
            }
        }

        @Override
        public void onError(Throwable throwable) {
            result.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            result.complete(buffer.toString(StandardCharsets.UTF_8));
        }
    }
}
