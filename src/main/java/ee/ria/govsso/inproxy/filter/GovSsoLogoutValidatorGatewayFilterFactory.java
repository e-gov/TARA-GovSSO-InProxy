package ee.ria.govsso.inproxy.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;

@Slf4j
@Component
public class GovSsoLogoutValidatorGatewayFilterFactory extends AbstractGatewayFilterFactory<GovSsoLogoutValidatorGatewayFilterFactory.Config> {

    public GovSsoLogoutValidatorGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            MultiValueMap<String, String> queryParams = exchange.getRequest()
                    .getQueryParams();

            String idToken = getFirstIdTokenValue(queryParams);

            if (idToken != null && !idToken.isEmpty() && exchange.getRequest().getMethod().equals(HttpMethod.GET)) {
                String idTokenPayload = getIdTokenPayload(idToken);

                if (idTokenPayload != null && idTokenPayload.contains("representee_list")) {
                    return createErrorResponse(exchange, "Logout+request+must+use+POST+method+if+the+id+token+from+%27id_token_hint%27+parameter+contains+a+%27representee_list%27+claim");
                }
            } else if (idToken != null && !idToken.isEmpty() && exchange.getRequest().getMethod().equals(HttpMethod.POST)) {
                return createErrorResponse(exchange, "The+%27id_token_hint%27+query+parameter+is+not+allowed+when+using+logout+request+with+http+POST+method%2C+it+must+be+passed+as+a+form+parameter");
            }

            return chain.filter(exchange);
        };
    }

    private static String getIdTokenPayload(String idToken) {
        try {
            String[] chunks = idToken.split("\\.", 3);
            Base64.Decoder decoder = Base64.getUrlDecoder();
            if (chunks.length > 1) {
                return new String(decoder.decode(chunks[1]));
            } else {
                return null;
            }
        } catch (IllegalArgumentException e) {
            log.info("Unable to decode URL-encoded string: ", e);
            return null;
        }
    }

    private String getFirstIdTokenValue(MultiValueMap<String, String> map) {
        for (String k : map.keySet()) {
            if (k.equals("id_token_hint")) {
                return map.getFirst(k);
            }
        }
        return null;
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().clear();
        response.getHeaders().add(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=" + message);
        response.getHeaders().add(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
        ServerWebExchangeUtils.setResponseStatus(exchange, HttpStatus.FOUND);
        ServerWebExchangeUtils.setAlreadyRouted(exchange);

        return response.setComplete();
    }

    public static class Config {
    }
}
