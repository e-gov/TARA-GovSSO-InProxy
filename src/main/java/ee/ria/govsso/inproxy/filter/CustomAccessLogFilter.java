package ee.ria.govsso.inproxy.filter;

import ee.ria.govsso.inproxy.logging.CountingServerHttpResponseDecorator;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.AbstractServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.netty.http.server.HttpServerRequest;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.ZonedDateTime;
import java.util.Optional;

import static ee.ria.govsso.inproxy.filter.IpAddressGatewayFilterFactory.CLIENT_ID_ATTR;
import static java.util.Objects.requireNonNullElse;

@Component
@ConditionalOnBooleanProperty("tara-govsso-inproxy.enable-access-log")
@Order(Ordered.LOWEST_PRECEDENCE)
@RequiredArgsConstructor
public class CustomAccessLogFilter implements WebFilter {

    private static final Logger logger = LoggerFactory.getLogger(CustomAccessLogFilter.class);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        long startTimeMillis = System.currentTimeMillis();
        ZonedDateTime requestTime = ZonedDateTime.now();

        CountingServerHttpResponseDecorator decoratedResponse =
                new CountingServerHttpResponseDecorator(exchange.getResponse());
        ServerWebExchange mutatedExchange = exchange.mutate()
                .response(decoratedResponse)
                .build();

        return chain.filter(mutatedExchange)
                .doFinally(signalType -> {
                    long duration = System.currentTimeMillis() - startTimeMillis;

                    String clientId = mutatedExchange.getAttribute(CLIENT_ID_ATTR);

                    String remoteAddr = getRemoteAddr(exchange);
                    String method = mutatedExchange.getRequest().getMethod().name();
                    String uri = mutatedExchange.getRequest().getPath().toString();

                    String protocol = "unknown";
                    if (mutatedExchange.getRequest() instanceof AbstractServerHttpRequest abstractserverhttprequest) {
                        HttpServerRequest nativeRequest = abstractserverhttprequest.getNativeRequest();
                        protocol = nativeRequest.version().text();
                    }

                    HttpStatusCode statusCode = mutatedExchange.getResponse().getStatusCode();

                    long realContentLength = decoratedResponse.getByteCount();

                    String logMessage = String.format("%s - %s [%s] \"%s %s %s\" %s %s %d",
                            requireNonNullElse(remoteAddr, "-"),
                            requireNonNullElse(clientId, "-"),
                            requestTime,
                            method,
                            uri,
                            protocol,
                            (statusCode != null) ? String.valueOf(statusCode.value()) : "-",
                            (realContentLength > 0) ? String.valueOf(realContentLength) : "-",
                            duration);

                    logger.info(logMessage);
                });
    }

    private String getRemoteAddr(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                .map(InetSocketAddress::getAddress)
                .map(InetAddress::getHostAddress)
                .orElse(null);
    }
}
