package ee.ria.govsso.inproxy.configuration.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;

import java.util.HashSet;
import java.util.Set;

@Profile("govsso")
@ConfigurationProperties("tara-govsso-inproxy.govsso")
@Data
public class GovSsoConfigurationProperties {

    AllowLogoutRepresenteeListScopeQueryParam allowLogoutRepresenteeListScopeQueryParam = new AllowLogoutRepresenteeListScopeQueryParam();

    @Data
    public static class AllowLogoutRepresenteeListScopeQueryParam {

        Set<String> clientIds = new HashSet<>();

    }

}
