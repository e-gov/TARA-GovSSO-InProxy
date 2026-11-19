package ee.ria.govsso.inproxy.configuration;

import ee.ria.govsso.inproxy.configuration.properties.XForwardedForConfigurationProperties;
import ee.ria.govsso.inproxy.filter.EidUseXForwardedForFilter;
import ee.ria.govsso.inproxy.filter.EidSetXForwardedForHeaderFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.headers.RemoveXForwardedHeadersFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class XForwardedForConfiguration {

    @Bean
    public EidUseXForwardedForFilter useXForwardedForFilter(XForwardedForConfigurationProperties properties) {
        EidUseXForwardedForFilter.TrustStrategy trustStrategy =
                switch (properties.trustUpstreamHeaders().strategy()) {
                    case ALWAYS -> EidUseXForwardedForFilter.TrustStrategy.always();
                    case NEVER -> EidUseXForwardedForFilter.TrustStrategy.never();
                };
        return new EidUseXForwardedForFilter(trustStrategy);
    }

    @Bean
    public EidSetXForwardedForHeaderFilter setXForwardedForHeaderFilter(
            XForwardedForConfigurationProperties properties,
            /* `SetXForwardedForFilter` works best in conjunction with `RemoveXForwardedHeadersFilter`, that should be
             * created by `GatewayAutoConfiguration`. While it is not an explicit dependency for
             * `SetXForwardedForFilter`, it makes sense to check that the two are configured to properly work with
             * each-other. */
            RemoveXForwardedHeadersFilter removeXForwardedHeadersFilter,
            @Value("server.forward-headers-strategy") String forwardHeadersStrategy
    ) {
        EidSetXForwardedForHeaderFilter result = new EidSetXForwardedForHeaderFilter(properties.appendProximalClientIp());
        validateXForwardedHeaderFiltersConfiguration(result, removeXForwardedHeadersFilter);
        validateBuiltInForwardedHeadersHandlingDisabled(forwardHeadersStrategy);
        return result;
    }

    private static void validateBuiltInForwardedHeadersHandlingDisabled(String forwardHeadersStrategy) {
        if ("NONE".equalsIgnoreCase(forwardHeadersStrategy)) {
            throw new IllegalStateException(
                    "`server.forward-headers-strategy` values other than `NONE` are not supported " +
                            "as they might clash with the custom `X-Forwarded-For` handling");
        }
    }

    private void validateXForwardedHeaderFiltersConfiguration(
            EidSetXForwardedForHeaderFilter eidSetXForwardedForHeaderFilter,
            RemoveXForwardedHeadersFilter removeXForwardedHeadersFilter
    ) {
        if (removeXForwardedHeadersFilter == null) {
            throw new IllegalStateException(
                    "Check your configuration, `RemoveXForwardedHeadersFilter` bean is missing, " +
                            "which probably means multiple filters are trying to set " +
                            "down-stream \"X-Forwarded-For\" headers.");
        }
        if (eidSetXForwardedForHeaderFilter.getOrder() <= removeXForwardedHeadersFilter.getOrder()) {
            throw new IllegalStateException(
                    "`SetXForwardedForFilter` should be after `RemoveXForwardedHeadersFilter` in the filter order");
        }
    }

}
