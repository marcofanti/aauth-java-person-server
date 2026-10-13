package io.github.marcofanti.aauth.personserver.ps;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.spi.InetAddressResolver;
import java.net.spi.InetAddressResolverProvider;
import java.util.List;
import java.util.stream.Stream;

/**
 * The JVM-wide resolver (JEP 418) that closes the DNS-rebinding gap in {@link Egress}: a host
 * {@link Egress} has just validated resolves to the addresses it validated, so the HTTP client
 * connects to exactly those, whatever the DNS answers next. Every other lookup goes to the
 * built-in resolver unchanged. Registered in {@code META-INF/services}.
 */
public final class EgressResolverProvider extends InetAddressResolverProvider {

    private static volatile InetAddressResolver builtin;

    @Override
    public InetAddressResolver get(Configuration configuration) {
        builtin = configuration.builtinResolver();
        return new PinningResolver(configuration.builtinResolver());
    }

    @Override
    public String name() {
        return "aauth-egress-pinning";
    }

    /** The built-in resolver once this provider is installed, else {@code null}. */
    static InetAddressResolver builtin() {
        return builtin;
    }

    /** Answers pinned hosts from their pins, everything else from {@code delegate}. */
    static final class PinningResolver implements InetAddressResolver {

        private final InetAddressResolver delegate;

        PinningResolver(InetAddressResolver delegate) {
            this.delegate = delegate;
        }

        @Override
        public Stream<InetAddress> lookupByName(String host, LookupPolicy lookupPolicy) throws UnknownHostException {
            List<InetAddress> pinned = Egress.pinned(host);
            if (pinned == null) {
                return delegate.lookupByName(host, lookupPolicy);
            }
            int characteristics = lookupPolicy.characteristics();
            boolean ipv4 = (characteristics & LookupPolicy.IPV4) != 0;
            boolean ipv6 = (characteristics & LookupPolicy.IPV6) != 0;
            List<InetAddress> allowed = pinned.stream()
                    .filter(address ->
                            (ipv4 && address instanceof Inet4Address) || (ipv6 && address instanceof Inet6Address))
                    .toList();
            if (allowed.isEmpty()) {
                throw new UnknownHostException(host + " has no pinned address of the requested family");
            }
            return allowed.stream();
        }

        @Override
        public String lookupByAddress(byte[] addr) throws UnknownHostException {
            return delegate.lookupByAddress(addr);
        }
    }
}
