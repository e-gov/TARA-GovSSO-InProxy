package ee.ria.govsso.inproxy.filter;


import ee.ria.govsso.inproxy.util.forwarded.ParsedXForwardedForUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.headers.HttpHeadersFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.commons.lang3.StringUtils.isNotBlank;

@RequiredArgsConstructor
public class EidSetXForwardedForHeaderFilter implements HttpHeadersFilter, Ordered {

    public static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private final boolean appendProximateClientIp;

    @Override
    public HttpHeaders filter(HttpHeaders headers, ServerWebExchange exchange) {
        HttpHeaders result = copyOf(headers);
        String headerValue = computeHeaderValue(exchange);
        if (isNotBlank(headerValue)) {
            result.set(X_FORWARDED_FOR, headerValue);
        } else {
            result.remove(X_FORWARDED_FOR);
        }
        return result;
    }

    private String computeHeaderValue(ServerWebExchange exchange) {
        String parsedXffValue = ParsedXForwardedForUtil.get(exchange);
        String ipToAppend = appendProximateClientIp ? getRemoteIp(exchange.getRequest()) : null;
        return Stream.of(parsedXffValue, ipToAppend)
                .filter(Objects::nonNull)
                .collect(Collectors.joining(", "));
    }

    private HttpHeaders copyOf(HttpHeaders original) {
        HttpHeaders result = new HttpHeaders();
        for (Map.Entry<String, List<String>> header : original.headerSet()) {
            result.addAll(header.getKey(), header.getValue());
        }
        return result;
    }

    private String getRemoteIp(ServerHttpRequest request) {
        return Optional.of(request)
                .map(ServerHttpRequest::getRemoteAddress)
                .map(InetSocketAddress::getAddress)
                .map(InetAddress::getHostAddress)
                .orElse(null);
    }

    @Override
    public int getOrder() {
        return 1;
    }
}
