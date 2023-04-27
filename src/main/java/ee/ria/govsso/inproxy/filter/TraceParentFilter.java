package ee.ria.govsso.inproxy.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;

@Component
public class TraceParentFilter extends AbstractGatewayFilterFactory<TraceParentFilter.Config> {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";

    public TraceParentFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            MultiValueMap<String, String> queryParams = exchange.getRequest()
                    .getQueryParams();
            String traceParentValue = getFirstTraceParentValueIgnoringCase(queryParams);

            if (traceParentValue != null && !traceParentValue.isEmpty()) {
                exchange.getRequest().mutate()
                        .headers(headers -> headers.add(TRACE_PARENT_PARAMETER_NAME, traceParentValue));
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

    public static class Config {}
}
