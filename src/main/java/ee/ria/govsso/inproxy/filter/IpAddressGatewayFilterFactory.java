package ee.ria.govsso.inproxy.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.exception.HydraStyleException;
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
import org.springframework.http.server.reactive.ServerHttpRequest;
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
    public static final String X_CLIENT_ID_HEADER = "X-ClientId";

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
            String clientId = null;
            try {
                String requestIpAddress = exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
                clientId = getClientId(exchange);
                if (clientId == null) {
                    throw new HydraStyleException(
                            "invalid_grant", "The provided authorization grant is invalid.", HttpStatus.BAD_REQUEST);
                } else if (!tokenRequestAllowedIpAddressesService.isTokenRequestAllowed(clientId, requestIpAddress)) {
                    if (ipBlockEnabled){
                        throw new HydraStyleException(
                                "unauthorized_client",
                                String.format("IP address %s is not whitelisted for client_id \"%s\"", requestIpAddress, clientId),
                                HttpStatus.BAD_REQUEST);
                    }
                    log.warn(String.format("unauthorized_client - IP address %s is not whitelisted for client_id \"%s\", allowing request", requestIpAddress, clientId), exchange);
                }

                // Adding X-ClientId header for Netty accesslog
                return chain.filter(addXClientIdHeader(clientId, exchange));
            } catch (HydraStyleException e) {
                return createErrorResponse(addXClientIdHeader(clientId, exchange), e);
            }
        };
    }

    private ServerWebExchange addXClientIdHeader(String clientId, ServerWebExchange exchange)  {
        // The header is only used internally within the inproxy to pass information between components; while it’s included in requests to Hydra, Hydra doesn’t need it
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
            .header(X_CLIENT_ID_HEADER, clientId)
            .build();
        return exchange.mutate().request(mutatedRequest).build();
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange, HydraStyleException e) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().clear();
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, "application/json");
        response.getHeaders().add(HttpHeaders.CACHE_CONTROL, "no-store");
        response.getHeaders().add(HttpHeaders.PRAGMA, "no-cache");
        ServerWebExchangeUtils.setResponseStatus(exchange, e.getStatusCode());
        ServerWebExchangeUtils.setAlreadyRouted(exchange);

        final Map<String, String> responseBody = Map.of(
                "error", e.getError(),
                "error_description", e.getErrorDescription());

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
        if (authorization == null) {
            return null;
        }
        authorization = authorization.trim();
        if (authorization.toLowerCase().startsWith(AUTHENTICATION_SCHEME_BASIC)) {
            return getClientIdFromBasicAuthorization(authorization);
        }
        return null;
    }

    private static String getClientIdFromBasicAuthorization(String authorization) {
        String base64Credentials = authorization.substring(AUTHENTICATION_SCHEME_BASIC.length()).trim();
        try {
            byte[] credDecoded = Base64.getDecoder().decode(base64Credentials);
            // UTF-8 as per https://datatracker.ietf.org/doc/html/rfc6749#appendix-B
            String[] credentials = new String(credDecoded, StandardCharsets.UTF_8).split(":", 2);
            // As per https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.1, this also applies when client_id
            // and client_secret are used in HTTP Basic authentication:
            // > The client identifier is encoded using the "application/x-www-form-urlencoded" encoding algorithm
            // > per Appendix B, and the encoded value is used as the username; the client password is encoded using
            // > the same algorithm and used as the password.
            String clientId = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8);
            if (clientId.isEmpty()) {
                throw new IllegalArgumentException("Empty client ID");
            }
            return clientId;
        } catch (IllegalArgumentException e) {
            throw new HydraStyleException(
                    "invalid_grant",
                    "The provided authorization grant is invalid.",
                    HttpStatus.BAD_REQUEST,
                    e);
        }
    }

    private String getClientIdFromBody(ServerWebExchange exchange) {
        // Request body must be application/x-www-form-urlencoded as per https://openid.net/specs/openid-connect-core-1_0.html#FormSerialization
        // "Content-Type: application/x-www-form-urlencoded" header is not checked.
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
                    // UTF-8 as per https://datatracker.ietf.org/doc/html/rfc6749#appendix-B
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
