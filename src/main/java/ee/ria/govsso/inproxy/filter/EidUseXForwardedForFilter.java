package ee.ria.govsso.inproxy.filter;

import ee.ria.govsso.inproxy.util.forwarded.ParsedXForwardedForUtil;
import inet.ipaddr.IPAddress;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.IPAddressStringParameters;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.StringTokenizer;

@Slf4j
@RequiredArgsConstructor
public class EidUseXForwardedForFilter implements WebFilter, Ordered {

    public static final int ORDER = Ordered.HIGHEST_PRECEDENCE;
    public static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private static final IPAddressStringParameters IP_PARAMS =
            new IPAddressStringParameters.Builder().allowEmpty(false).toParams();

    private final EidUseXForwardedForFilter.TrustStrategy trustStrategy;

    @Override
    public Mono<Void> filter(ServerWebExchange originalExchange, WebFilterChain chain) {
        String xffValue;
        InetSocketAddress remoteIp;
        try {
            ServerHttpRequest originalRequest = originalExchange.getRequest();
            if (!trustStrategy.shouldTrust(originalRequest)) {
                log.debug("Not trusting {} header value of request", X_FORWARDED_FOR);
                return chain.filter(originalExchange);
            }
            xffValue = parseXffHeaderValue(originalRequest);
            if (xffValue == null) {
                return chain.filter(originalExchange);
            }
            remoteIp = resolveRemoteIp(xffValue);
            if (remoteIp == null) {
                return chain.filter(originalExchange);
            }
        } catch (Exception e) {
            log.atError()
                    .setCause(e)
                    .log("Unexpected error while parsing {} header", X_FORWARDED_FOR);
            return chain.filter(originalExchange);
        }
        ServerWebExchange mutatedExchange = originalExchange.mutate()
                .request(request -> request.remoteAddress(remoteIp))
                .build();
        ParsedXForwardedForUtil.set(mutatedExchange, xffValue);
        return chain.filter(mutatedExchange);
    }

    private String parseXffHeaderValue(ServerHttpRequest request) {
        List<String> headerValues = request.getHeaders().getOrEmpty(X_FORWARDED_FOR);
        if (headerValues.isEmpty()) {
            return null;
        }
        if (headerValues.size() > 1) {
            log.debug("Multiple {} headers present, ignoring all", X_FORWARDED_FOR);
            return null;
        }
        return headerValues.get(0);
    }

    private InetSocketAddress resolveRemoteIp(String xffValue) {
        String lastHop = extractLastHop(xffValue);
        if (lastHop == null) {
            log.warn("Failed to extract last hop from {} header value \"{}\"", X_FORWARDED_FOR, xffValue);
            return null;
        }
        try {
            InetAddress inetAddress = parseIp(lastHop);
            return new InetSocketAddress(inetAddress, 0);
        } catch (Exception e) {
            log.atWarn()
                    .setCause(e)
                    .log("Failed to parse IP \"{}\"", lastHop);
            return null;
        }
    }

    private String extractLastHop(String xffValue) {
        StringTokenizer tokenizer = new StringTokenizer(xffValue, ",");
        String result = null;
        while (tokenizer.hasMoreTokens()) {
            result = tokenizer.nextToken();
        }
        return result;
    }

    private InetAddress parseIp(String value) {
        String cleanValue = StringUtils.trimToNull(value);
        IPAddress address = new IPAddressString(cleanValue, IP_PARAMS).getAddress();
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

    @Override
    public int getOrder() {
        return ORDER;
    }

    @FunctionalInterface
    public interface TrustStrategy {

        boolean shouldTrust(ServerHttpRequest request);

        static EidUseXForwardedForFilter.TrustStrategy always() {
            return request -> true;
        }

        static EidUseXForwardedForFilter.TrustStrategy never() {
            return request -> false;
        }

    }
}
