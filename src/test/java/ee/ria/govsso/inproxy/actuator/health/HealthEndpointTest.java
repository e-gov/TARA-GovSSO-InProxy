package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.BaseTest;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import io.restassured.response.ValidatableResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.test.context.ActiveProfiles;

import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@ActiveProfiles({"govsso"})
@RequiredArgsConstructor
abstract class HealthEndpointTest extends BaseTest {

    private final TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    void mockAdminHealthIndicatorUp() {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)));
        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();
    }

    void mockAdminHealthIndicatorDown() {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(400)));
        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();
    }

    void assertCertificatesHealthUp(ValidatableResponse response, String prefix) {
        response.body(prefix + "status", equalTo("UP"))
                // TODO Verifying serverKeyStore would require setting up TLS between REST Assured client and Spring
                //  Boot server.
                .body(prefix + "components.keySet()", equalTo(Set.of("adminTrustStore", "gatewayTrustStore")))
                .body(prefix + "components.adminTrustStore.status", equalTo("UP"))
                .body(prefix + "components.adminTrustStore.details.certificates[0]", notNullValue())
                .body(prefix + "components.adminTrustStore.details.certificates[0].alias", equalTo("govsso-ca.localhost"))
                .body(prefix + "components.adminTrustStore.details.certificates[0].subjectDN", equalTo("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE"))
                .body(prefix + "components.adminTrustStore.details.certificates[0].serialNumber", notNullValue())
                .body(prefix + "components.adminTrustStore.details.certificates[0].state", equalTo("ACTIVE"))
                .body(prefix + "components.adminTrustStore.details.certificates[1].", nullValue())
                .body(prefix + "components.gatewayTrustStore.status", equalTo("UP"))
                .body(prefix + "components.gatewayTrustStore.details.certificates[0]", notNullValue())
                .body(prefix + "components.gatewayTrustStore.details.certificates[0].alias", equalTo("govsso-ca.localhost"))
                .body(prefix + "components.gatewayTrustStore.details.certificates[0].subjectDN", equalTo("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE"))
                .body(prefix + "components.gatewayTrustStore.details.certificates[0].serialNumber", notNullValue())
                .body(prefix + "components.gatewayTrustStore.details.certificates[0].state", equalTo("ACTIVE"))
                .body(prefix + "components.gatewayTrustStore.details.certificates[1].", nullValue());
    }
}
