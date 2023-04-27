package ee.ria.govsso.inproxy.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Component
public class PromptFilter extends AbstractGatewayFilterFactory<PromptFilter.Config> {

    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_VALUE = "consent";

    public PromptFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            MultiValueMap<String, String> queryParams = exchange.getRequest()
                    .getQueryParams();
            String[] promptKeyAndValue = getFirstPromptParameterIgnoringCase(queryParams);

            if (promptKeyAndValue == null || promptKeyAndValue[1] == null || promptKeyAndValue[1].isEmpty()) {
                String promptParameterName = promptKeyAndValue == null ? PROMPT_PARAMETER_NAME : promptKeyAndValue[0];
                URI newUri = UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
                        .replaceQueryParam(promptParameterName, PROMPT_PARAMETER_VALUE).build().toUri();
                ServerHttpRequest newRequest = exchange.getRequest().mutate()
                        .uri(newUri).build();
                return chain.filter(exchange.mutate().request(newRequest).build());
            }
            return chain.filter(exchange);
        };
    }

    private String[] getFirstPromptParameterIgnoringCase(MultiValueMap<String, String> map) {
        for (String k : map.keySet()) {
            if (k.equalsIgnoreCase(PROMPT_PARAMETER_NAME)) {
                return new String[]{k, map.getFirst(k)};
            }
        }
        return null;
    }

    public static class Config {}
}
