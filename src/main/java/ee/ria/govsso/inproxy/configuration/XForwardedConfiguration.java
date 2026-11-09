package ee.ria.govsso.inproxy.configuration;

import ee.ria.govsso.inproxy.configuration.properties.ForwardedForConfigurationProperties;
import ee.ria.govsso.inproxy.filter.SetXForwardedForHeaderFilter;
import ee.ria.govsso.inproxy.util.forwarded.ForwardedChainRemoteAddressResolver;
import ee.ria.govsso.inproxy.util.forwarded.ForwardedChainResolver;
import ee.ria.govsso.inproxy.util.forwarded.XForwardedForForwardedChainResolver;
import org.springframework.cloud.gateway.filter.headers.RemoveXForwardedHeadersFilter;
import org.springframework.cloud.gateway.support.ipresolver.RemoteAddressResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class XForwardedConfiguration {

    @Bean
    public ForwardedChainResolver forwardedChainResolver(ForwardedForConfigurationProperties properties) {
        XForwardedForForwardedChainResolver.TrustStrategy trustStrategy =
                switch (properties.trustUpstreamHeaders().strategy()) {
                    case ALWAYS -> XForwardedForForwardedChainResolver.TrustStrategy.always();
                    case NEVER -> XForwardedForForwardedChainResolver.TrustStrategy.never();
                };
        return new XForwardedForForwardedChainResolver(trustStrategy);
    }

    @Bean
    public RemoteAddressResolver remoteAddressResolver(ForwardedChainResolver forwardedChainResolver) {
        return new ForwardedChainRemoteAddressResolver(forwardedChainResolver);
    }

    @Bean
    public SetXForwardedForHeaderFilter setXForwardedForHeaderFilter(
            ForwardedForConfigurationProperties properties,
            ForwardedChainResolver forwardedChainResolver,
            /* `SetXForwardedForFilter` works best in conjunction with `RemoveXForwardedHeadersFilter`, that should be
             * created by `GatewayAutoConfiguration`. While it is not an explicit dependency for
             * `SetXForwardedForFilter`, it makes sense to check that the two are configured to properly work with
             * each-other. */
            RemoveXForwardedHeadersFilter removeXForwardedHeadersFilter
    ) {
        SetXForwardedForHeaderFilter result = new SetXForwardedForHeaderFilter(
                properties.appendProximalClientIp(), forwardedChainResolver);
        validateXForwardedHeaderFiltersConfiguration(result, removeXForwardedHeadersFilter);
        return result;
    }

    private void validateXForwardedHeaderFiltersConfiguration(
            SetXForwardedForHeaderFilter setXForwardedForHeaderFilter,
            RemoveXForwardedHeadersFilter removeXForwardedHeadersFilter
    ) {
        if (removeXForwardedHeadersFilter == null) {
            throw new IllegalStateException(
                    "Check your configuration, `RemoveXForwardedHeadersFilter` bean is missing");
        }
        if (setXForwardedForHeaderFilter.getOrder() <= removeXForwardedHeadersFilter.getOrder()) {
            throw new IllegalStateException(
                    "`SetXForwardedForFilter` should be after `RemoveXForwardedHeadersFilter` in the filter order");
        }
    }

}
