package ee.ria.govsso.inproxy.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@Component
public class PromptGatewayFilterFactory extends AbstractGatewayFilterFactory<PromptGatewayFilterFactory.Config> {

    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_VALUE = "consent";

    public PromptGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            MultiValueMap<String, String> queryParams = exchange.getRequest()
                    .getQueryParams();
            String[] promptKeyAndValue = getFirstPromptParameterIgnoringCase(queryParams);

            // If query parameter "prompt" (case-insensitive) doesn't exist or it's value is empty,
            // then add/replace query parameter "prompt=consent" to proxiable HTTP request.
            if (promptKeyAndValue == null || promptKeyAndValue[1] == null || promptKeyAndValue[1].isEmpty()) {
                String promptParameterName = promptKeyAndValue == null ? PROMPT_PARAMETER_NAME : promptKeyAndValue[0];
                // We use UriComponents.toUriString() and create a new URI from that string, because using
                // UriComponents.toUri() method directly would re-encode the already encoded URI parameters,
                // causing "%3D" to be converted to "%253D", for example.
                String newUriString = UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
                        .replaceQueryParam(promptParameterName, PROMPT_PARAMETER_VALUE).build().toUriString();
                URI newUri = URI.create(newUriString);
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
