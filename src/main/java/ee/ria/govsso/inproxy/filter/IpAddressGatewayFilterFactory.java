package ee.ria.govsso.inproxy.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
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

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
public class IpAddressGatewayFilterFactory extends AbstractGatewayFilterFactory<IpAddressGatewayFilterFactory.Config> {

    public static final String AUTHENTICATION_SCHEME_BASIC = "basic";
    public static final String REQUEST_BODY_FORM_ELEMENT_KEY = "client_id";

    private final TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;
    private final Jackson2JsonEncoder jackson2JsonEncoder;

    @Value("${tara-govsso-inproxy.token-request-block-ip-addresses}")
    private boolean ipBlockEnabled;


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
                if(ipBlockEnabled){
                    return createErrorResponse(exchange, "unauthorized_client", String.format("Your IP address %s is not whitelisted", requestIpAddress));
                }
                log.warn(String.format("unauthorized_client - IP address %s is not whitelisted for client_id %s, allowing request", requestIpAddress, clientId), exchange);
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
        String clientIdFromHeader = getClientIdFromHeader(exchange);
        String clientIdFromBody = getClientIdFromBody(exchange);

        if (clientIdFromHeader == null) {
            return clientIdFromBody;
        } else if (clientIdFromBody == null) {
            return clientIdFromHeader;
        }

        if (StringUtils.equals(clientIdFromHeader, clientIdFromBody)) {
            return clientIdFromHeader;
        }

        return null;
    }

    private String getClientIdFromHeader(ServerWebExchange exchange) {
        String authorization = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorization != null) {
            authorization = authorization.trim();
            if (authorization.toLowerCase().startsWith(AUTHENTICATION_SCHEME_BASIC)
                    && !authorization.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
                String base64Credentials = authorization.substring(AUTHENTICATION_SCHEME_BASIC.length()).trim();
                byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
                String[] credentials = new String(credDecoded, StandardCharsets.UTF_8).split(":", 2);
                return credentials[0];
            }
        }
        return null;
    }

    private String getClientIdFromBody(ServerWebExchange exchange) {
        String requestBody = exchange.getAttribute(ServerWebExchangeUtils.CACHED_REQUEST_BODY_ATTR);
        if (requestBody != null) {
            Map<String, String> requestBodyMap = parseFormToMap(requestBody);
            if (requestBodyMap.containsKey(REQUEST_BODY_FORM_ELEMENT_KEY)) {
                return requestBodyMap.get(REQUEST_BODY_FORM_ELEMENT_KEY);
            }
        }
        return null;
    }

    private Map<String, String> parseFormToMap(String encodedString) {
        Map<String, String> map = new HashMap<>();
        try {
            String[] pairs = org.springframework.util.StringUtils.tokenizeToStringArray(encodedString, "&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=", 2);
                if (keyValue.length > 1) {
                    String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                    String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                    map.put(key, value);
                }
            }
        } catch (IllegalArgumentException e){
            log.info("Unable to decode URL-encoded string: ", e);
        }

        return map;
    }

    public static class Config {
    }
}
