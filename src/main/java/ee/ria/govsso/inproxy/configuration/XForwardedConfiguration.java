package ee.ria.govsso.inproxy.configuration;

import ee.ria.govsso.inproxy.configuration.properties.ForwardedForConfigurationProperties;
import ee.ria.govsso.inproxy.filter.EidUseXForwardedForFilter;
import ee.ria.govsso.inproxy.filter.EidSetXForwardedForHeaderFilter;
import org.springframework.cloud.gateway.filter.headers.RemoveXForwardedHeadersFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class XForwardedConfiguration {

    @Bean
    public EidUseXForwardedForFilter useXForwardedForFilter(ForwardedForConfigurationProperties properties) {
        EidUseXForwardedForFilter.TrustStrategy trustStrategy =
                switch (properties.trustUpstreamHeaders().strategy()) {
                    case ALWAYS -> EidUseXForwardedForFilter.TrustStrategy.always();
                    case NEVER -> EidUseXForwardedForFilter.TrustStrategy.never();
                };
        return new EidUseXForwardedForFilter(trustStrategy);
    }

    @Bean
    public EidSetXForwardedForHeaderFilter setXForwardedForHeaderFilter(
            ForwardedForConfigurationProperties properties,
            /* `SetXForwardedForFilter` works best in conjunction with `RemoveXForwardedHeadersFilter`, that should be
             * created by `GatewayAutoConfiguration`. While it is not an explicit dependency for
             * `SetXForwardedForFilter`, it makes sense to check that the two are configured to properly work with
             * each-other. */
            RemoveXForwardedHeadersFilter removeXForwardedHeadersFilter
    ) {
        EidSetXForwardedForHeaderFilter result = new EidSetXForwardedForHeaderFilter(properties.appendProximalClientIp());
        validateXForwardedHeaderFiltersConfiguration(result, removeXForwardedHeadersFilter);
        return result;
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
