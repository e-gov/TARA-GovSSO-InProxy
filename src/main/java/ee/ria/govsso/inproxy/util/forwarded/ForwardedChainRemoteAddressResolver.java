package ee.ria.govsso.inproxy.util.forwarded;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.support.ipresolver.RemoteAddressResolver;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.util.List;

@RequiredArgsConstructor
public class ForwardedChainRemoteAddressResolver implements RemoteAddressResolver {

    private final ForwardedChainResolver forwardedChainResolver;

    @Override
    public InetSocketAddress resolve(ServerWebExchange exchange) {
        List<String> chain = forwardedChainResolver.resolve(exchange.getRequest());
        if (chain.isEmpty()) {
            return RemoteAddressResolver.super.resolve(exchange);
        }
        String firstHop = chain.get(0);
        return new InetSocketAddress(firstHop, 0);
    }

}
