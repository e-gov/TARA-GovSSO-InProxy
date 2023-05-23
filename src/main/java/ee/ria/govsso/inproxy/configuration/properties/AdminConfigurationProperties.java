package ee.ria.govsso.inproxy.configuration.properties;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import java.net.URL;

@Validated
@ConfigurationProperties(prefix = "govsso-inproxy.admin")
public record AdminConfigurationProperties(
        @NotNull
        URL baseUrl,
        @Min(value = 1000) @DefaultValue("60000")
        int tokenRequestAllowedIpAddressesRefreshIntervalInMilliseconds,
        AdminTlsConfigurationProperties tls) {

    @Validated
    @ConfigurationProperties(prefix = "govsso-inproxy.admin.tls")
    public record AdminTlsConfigurationProperties(
            @NotNull
            Resource trustStore,
            @NotBlank
            String trustStorePassword,
            @DefaultValue("PKCS12")
            @NotNull
            String trustStoreType) {
    }
}
