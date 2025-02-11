package ee.ria.govsso.inproxy.filter;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.inproxy.configuration.properties.GovSsoConfigurationProperties;
import ee.ria.govsso.inproxy.exception.HydraStyleException;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.core5.net.URIBuilder;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.text.ParseException;
import java.util.List;

@Slf4j
@Component
@Profile("govsso")
public class GovSsoLogoutValidatorGatewayFilterFactory extends AbstractGatewayFilterFactory<GovSsoLogoutValidatorGatewayFilterFactory.Config> {

    private final GovSsoConfigurationProperties govSsoConfigurationProperties;

    public GovSsoLogoutValidatorGatewayFilterFactory(GovSsoConfigurationProperties govSsoConfigurationProperties) {
        super(Config.class);
        this.govSsoConfigurationProperties = govSsoConfigurationProperties;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            try {
                validateIdTokenHintQueryParam(exchange);
                return chain.filter(exchange);
            } catch (HydraStyleException e) {
                return createErrorResponse(exchange, e);
            }
        };
    }

    private void validateIdTokenHintQueryParam(ServerWebExchange exchange) {
        MultiValueMap<String, String> queryParams = exchange.getRequest()
                .getQueryParams();
        String idToken = getIdTokenQueryParam(queryParams);
        if (idToken == null) {
            return;
        }
        if (exchange.getRequest().getMethod().equals(HttpMethod.POST)) {
            throw new HydraStyleException(
                    HydraStyleException.INVALID_REQUEST,
                    "The 'id_token_hint' query parameter is not allowed when using logout request with http POST method, it must be passed as a form parameter");
        }
        if (exchange.getRequest().getMethod().equals(HttpMethod.GET)) {
            JWTClaimsSet jwtClaims;
            try {
                // Warning: The JWT signature is NOT verified, which is fine, but needs to be kept in mind when
                // using its data.
                SignedJWT jwt = SignedJWT.parse(idToken);
                jwtClaims = jwt.getJWTClaimsSet();
            } catch (ParseException e) {
                throw new HydraStyleException(
                        HydraStyleException.INVALID_REQUEST,
                        "The 'id_token_hint' query parameter value is not a valid JWS");
            }
            if (jwtClaims.getClaim("representee_list") == null) {
                return;
            }
            String clientId = getClientId(jwtClaims);
            if (!allowRepresenteeListScopeQueryParam(clientId)) {
                throw new HydraStyleException(
                        HydraStyleException.INVALID_REQUEST,
                        "Logout request must use POST method if the id token from 'id_token_hint' parameter contains a 'representee_list' claim");
            }
        }
    }

    private String getClientId(JWTClaimsSet jwtClaimsSet) {
        List<String> audience = jwtClaimsSet.getAudience();
        if (audience.isEmpty()) {
            throw new IllegalArgumentException("Can not determine client ID, no audience provided");
        }
        if (audience.size() != 1) {
            throw new IllegalArgumentException("Can not determine client ID, multiple audience claim values found");
        }
        return audience.get(0);
    }

    private String getIdTokenQueryParam(MultiValueMap<String, String> map) {
        List<String> idTokenHints = map.getOrDefault("id_token_hint", List.of());
        if(idTokenHints.isEmpty()) {
            return null;
        }
        if(idTokenHints.size() > 1) {
            throw new HydraStyleException(
                    HydraStyleException.INVALID_REQUEST,
                    "Multiple 'id_token_hint' query parameters found");
        }
        return idTokenHints.get(0);
    }

    private boolean allowRepresenteeListScopeQueryParam(String clientId) {
        return govSsoConfigurationProperties.getAllowLogoutRepresenteeListScopeQueryParam()
                .getClientIds()
                .contains(clientId);
    }

    private Mono<Void> createErrorResponse(ServerWebExchange exchange, HydraStyleException e) {
        String location = new URIBuilder()
                .appendPathSegments("error", "oidc")
                .addParameter("error", e.getError())
                .addParameter("error_description", e.getErrorDescription())
                .toString();
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().clear();
        response.getHeaders().add(HttpHeaders.LOCATION, location);
        response.getHeaders().add(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
        ServerWebExchangeUtils.setResponseStatus(exchange, HttpStatus.FOUND);
        ServerWebExchangeUtils.setAlreadyRouted(exchange);

        return response.setComplete();
    }

    public static class Config {
    }
}
