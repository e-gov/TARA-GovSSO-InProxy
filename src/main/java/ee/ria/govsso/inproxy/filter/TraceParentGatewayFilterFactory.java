package ee.ria.govsso.inproxy.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;

@Component
public class TraceParentGatewayFilterFactory extends AbstractGatewayFilterFactory<TraceParentGatewayFilterFactory.Config> {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";

    public TraceParentGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            MultiValueMap<String, String> queryParams = exchange.getRequest()
                    .getQueryParams();
            String traceParentValue = getFirstTraceParentValueIgnoringCase(queryParams);

            if (traceParentValue != null && !traceParentValue.isEmpty()) {
                return chain.filter(exchange.mutate()
                    .request(request -> request.header(TRACE_PARENT_PARAMETER_NAME, traceParentValue))
                    .build());
            }
            return chain.filter(exchange);
        };
    }

    private String getFirstTraceParentValueIgnoringCase(MultiValueMap<String, String> map) {
        for (String k : map.keySet()) {
            if (k.equalsIgnoreCase(TRACE_PARENT_PARAMETER_NAME)) {
                return map.getFirst(k);
            }
        }
        return null;
    }

    public static class Config {
    }
}
