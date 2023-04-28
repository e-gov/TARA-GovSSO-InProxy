package ee.ria.govsso.inproxy.configuration.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.net.URL;

@Validated
@ConstructorBinding
@ConfigurationProperties(prefix = "govsso-inproxy.admin")
public record AdminConfigurationProperties(
        @NotNull
        URL baseUrl,
        @Min(value = 1000) @DefaultValue("60000")
        int refreshTokenRequestAllowedIpAddressesIntervalInMilliseconds,
        AdminTlsConfigurationProperties tls) {

    @Validated
    @ConstructorBinding
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
