package ee.ria.govsso.inproxy.service;

import ee.ria.govsso.inproxy.BaseTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

class TokenRequestAllowedIpAddressesServiceTest extends BaseTest {

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @Test
    void hydra_tokenRequestAllowedIpAddressesRequestRespondsWith200_allowedIpAddressesAreSaved() {

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"client-a\":[\"127.0.0.1\"]}")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();
        boolean isTokenRequestAllowed = tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-a", "127.0.0.1");
        assertThat(isTokenRequestAllowed, is(true));
    }

    @Test
    void hydra_tokenRequestAllowedIpAddressesRequestRespondsWithEmptyBody_NoErrorIsThrown() {

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();
        tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-a", "1.1.1.1");
    }

}