package ee.ria.govsso.inproxy.configuration.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "tara-govsso-inproxy.forwarded-for")
@Validated
public record ForwardedForConfigurationProperties(
    @NotNull
    Boolean appendProximalClientIp,
    @NotNull @Validated
    TrustUpstreamHeaders trustUpstreamHeaders
) {

    public record TrustUpstreamHeaders(
            @NotNull Strategy strategy
    ) {

        public enum Strategy {
            ALWAYS,
            NEVER
        }
    }

}
