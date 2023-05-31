package ee.ria.govsso.inproxy.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.ResolvableType;
import org.springframework.core.codec.Hints;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.json.Jackson2JsonEncoder;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Component
public class IpAddressGatewayFilterFactory extends AbstractGatewayFilterFactory<IpAddressGatewayFilterFactory.Config> {

    public static final String AUTHENTICATION_SCHEME_BASIC = "basic";

    private final TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;
    private final Jackson2JsonEncoder jackson2JsonEncoder;

    public IpAddressGatewayFilterFactory(TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService,
                                         ObjectMapper objectMapper) {
        super(Config.class);
        this.tokenRequestAllowedIpAddressesService = tokenRequestAllowedIpAddressesService;
        jackson2JsonEncoder = new Jackson2JsonEncoder(objectMapper);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String clientId = getClientId(exchange);
            String requestIpAddress;

            requestIpAddress = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();

            if (clientId == null) {
                return createErrorResponse(exchange, "invalid_grant", "The provided authorization grant is invalid.");
            } else if (!tokenRequestAllowedIpAddressesService.isTokenRequestAllowed(clientId, requestIpAddress)) {
                return createErrorResponse(exchange, "unauthorized_client", String.format("Your IP address %s is not whitelisted", requestIpAddress));
            }

            return chain.filter(exchange);
        };
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange, String error, String errorDescription) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().clear();
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        response.getHeaders().add(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getHeaders().add(HttpHeaders.PRAGMA, "no-cache");
        ServerWebExchangeUtils.setResponseStatus(exchange, HttpStatus.BAD_REQUEST);
        ServerWebExchangeUtils.setAlreadyRouted(exchange);

        final Map<String, String> responseBody = Map.of(
                "error", error,
                "error_description", errorDescription);

        return response.writeWith(jackson2JsonEncoder.encode(Mono.just(responseBody),
                response.bufferFactory(),
                ResolvableType.forInstance(responseBody),
                MediaType.APPLICATION_JSON,
                Hints.from(Hints.LOG_PREFIX_HINT, exchange.getLogPrefix()))
        );
    }

    private String getClientId(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization == null) {
            return null;
        }
        authorization = authorization.trim();
        if (authorization.toLowerCase().startsWith(AUTHENTICATION_SCHEME_BASIC)
                && !authorization.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            String base64Credentials = authorization.substring(AUTHENTICATION_SCHEME_BASIC.length()).trim();
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            String[] credentials = new String(credDecoded, StandardCharsets.UTF_8).split(":", 2);
            return credentials[0];
        } else {
            return null;
        }
    }

    public static class Config {
    }
}
