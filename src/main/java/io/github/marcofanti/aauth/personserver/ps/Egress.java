package io.github.marcofanti.aauth.personserver.ps;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpResponse;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolver.LookupPolicy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ConcurrentHashMap;
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
 * <p>A host that passes is pinned to the addresses just checked for {@link #PIN_TTL}, and
 * {@link EgressResolverProvider} answers the HTTP client's own lookup from that pin, so a DNS
 * answer that changes between the check and the connection (rebinding) cannot reach an internal
 * address. Without that provider installed the check falls back to {@link InetAddress} and the
 * gap remains; {@link #pinningActive()} reports which applies.
 */
public final class Egress {

    /** Largest response body the PS reads from a peer. */
    public static final int MAX_BODY_BYTES = 1 << 20;

    /** How long a validated host stays pinned to the addresses checked. */
    public static final Duration PIN_TTL = Duration.ofSeconds(60);

    private static final int MAX_PINS = 10_000;

    private record Pin(List<InetAddress> addresses, Instant expires) {}

    private static volatile Set<String> allowedHosts = parse(System.getenv("AAUTH_PS_EGRESS_ALLOW_HOSTS"));
    private static final Map<String, Pin> pins = new ConcurrentHashMap<>();

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
        InetAddress literal = literal(host);
        if (literal != null) {
            refuseInternal(host, List.of(literal));
            return uri;
        }
        List<InetAddress> addresses;
        try {
            addresses = resolve(host);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("egress refused: cannot resolve " + host, e);
        }
        refuseInternal(host, addresses);
        pin(host, addresses, Instant.now().plus(PIN_TTL));
        return uri;
    }

    private static void refuseInternal(String host, List<InetAddress> addresses) {
        for (InetAddress address : addresses) {
            if (isInternal(address)) {
                throw new IllegalArgumentException("egress refused: " + host + " resolves to internal address "
                        + address.getHostAddress() + "; allow it with AAUTH_PS_EGRESS_ALLOW_HOSTS");
            }
        }
    }

    /** The address an IP-literal host names (IPv6 in brackets), or {@code null} for a host name. */
    private static InetAddress literal(String host) {
        String bare = host.startsWith("[") && host.endsWith("]") ? host.substring(1, host.length() - 1) : host;
        try {
            return InetAddress.ofLiteral(bare);
        } catch (IllegalArgumentException notALiteral) {
            return null;
        }
    }

    /** Fresh addresses for {@code host}: from the built-in resolver, bypassing pins and the JVM cache. */
    private static List<InetAddress> resolve(String host) throws UnknownHostException {
        InetAddressResolver builtin = EgressResolverProvider.builtin();
        if (builtin == null) {
            return List.of(InetAddress.getAllByName(host));
        }
        List<InetAddress> addresses = builtin.lookupByName(host, LookupPolicy.of(LookupPolicy.IPV4 | LookupPolicy.IPV6))
                .toList();
        if (addresses.isEmpty()) {
            throw new UnknownHostException(host);
        }
        return addresses;
    }

    static void pin(String host, List<InetAddress> addresses, Instant expires) {
        if (pins.size() >= MAX_PINS) {
            Instant now = Instant.now();
            pins.values().removeIf(stale -> stale.expires().isBefore(now));
        }
        pins.put(host.toLowerCase(Locale.ROOT), new Pin(List.copyOf(addresses), expires));
    }

    /** The addresses {@code host} is pinned to, or {@code null} when it is not (or no longer) pinned. */
    static List<InetAddress> pinned(String host) {
        Pin pin = pins.get(host.toLowerCase(Locale.ROOT));
        return pin == null || pin.expires().isBefore(Instant.now()) ? null : pin.addresses();
    }

    /**
     * Whether the HTTP client's lookups go through {@link EgressResolverProvider}. The JVM loads
     * its resolver on the first lookup, so this makes one.
     */
    public static boolean pinningActive() {
        try {
            InetAddress.getByName("localhost");
        } catch (UnknownHostException ignored) {
            // The lookup only makes the JVM load its resolver; the answer does not matter.
        }
        return EgressResolverProvider.builtin() != null;
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
