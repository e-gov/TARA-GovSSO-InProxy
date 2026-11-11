package ee.ria.govsso.inproxy.util.forwarded;

import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.support.ipresolver.RemoteAddressResolver;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
public class ForwardedChainRemoteAddressResolver implements RemoteAddressResolver {

    private static final IPAddressStringParameters IP_PARAMS =
            new IPAddressStringParameters.Builder().allowEmpty(false).toParams();


    private final ForwardedChainResolver forwardedChainResolver;

    @Override
    public InetSocketAddress resolve(ServerWebExchange exchange) {
        InetSocketAddress result = doResolve(exchange);
        if (result == null) {
            return RemoteAddressResolver.super.resolve(exchange);
        }
        return result;
    }

    private InetSocketAddress doResolve(ServerWebExchange exchange) {
        List<String> chain = forwardedChainResolver.resolve(exchange.getRequest());
        if (chain.isEmpty()) {
            return null;
        }
        String firstHop = chain.get(0);
        try {
            InetAddress inetAddress = parseIp(firstHop);
            return new InetSocketAddress(inetAddress, 0);
        } catch (Exception e) {
            log.atWarn()
                    .setCause(e)
                    .log("Failed to parse IP \"{}\"", firstHop);
            return null;
        }
    }

    private InetAddress parseIp(String value) {
        IPAddress address = new IPAddressString(value, IP_PARAMS).getAddress();
        if (address == null) {
            throw new IllegalArgumentException("Invalid address");
        }
        if (address.isMultiple() || address.isPrefixed()) {
            throw new IllegalArgumentException("Address range is not allowed");
        }
        InetAddress inetAddress = address.toInetAddress();
        if (inetAddress == null) {
            throw new IllegalStateException("Unable to convert to `InetAddress`");
        }
        return inetAddress;
    }

}
