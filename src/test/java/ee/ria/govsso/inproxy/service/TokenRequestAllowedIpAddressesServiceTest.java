package ee.ria.govsso.inproxy.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.BaseTest;
import ee.ria.govsso.inproxy.configuration.properties.AdminConfigurationProperties;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static ch.qos.logback.classic.Level.INFO;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class TokenRequestAllowedIpAddressesServiceTest extends BaseTest {

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private AdminConfigurationProperties adminConfigurationProperties;

    @Test
    void admin_TokenRequestAllowedIpAddressesRequestRespondsWith200_AllowedIpAddressesAreStoredInMapAndSavedToFile() throws IOException {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"client-a\":[\"127.0.0.1\"]}")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        boolean isTokenRequestAllowed = tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-a", "127.0.0.1");
        Map<String, List<String>> tokenRequestAllowedIpAddresses = objectMapper.readValue(new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath()), new TypeReference<>() {
        });
        assertThat(isTokenRequestAllowed, is(true));
        assertThat(tokenRequestAllowedIpAddresses.get("client-a").get(0), equalTo("127.0.0.1"));
        assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN request", "http.request.method=GET, url.full=https://admin.localhost:17442//clients/tokenrequestallowedipaddresses");
        assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN response: 200", "http.response.status_code=200, http.response.body.content={\"client-a\":[\"127.0.0.1\"]}");
    }

    @Test
    void admin_TokenRequestAllowedIpAddressesRequestRespondsWith404_IpAddressesFileIsNotChanged() throws IOException {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(404)));

        createTokenRequestAllowedIpAddressesFile();
        tokenRequestAllowedIpAddressesService.loadIpAddressesFromFileIgnoringExceptions();
        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        assertErrorIsLogged("Unable to update the list of allowed IP-address ranges: 404 Not Found from GET https://admin.localhost:17442/clients/tokenrequestallowedipaddresses");
        boolean isTokenRequestAllowed = tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-from-file", "1.1.1.1");
        Map<String, List<String>> tokenRequestAllowedIpAddressesFromFile = objectMapper.readValue(new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath()), new TypeReference<>() {
        });
        assertThat(isTokenRequestAllowed, is(true));
        assertThat(tokenRequestAllowedIpAddressesFromFile.get("client-from-file").get(0), equalTo("1.1.1.1"));
        assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN request", "http.request.method=GET, url.full=https://admin.localhost:17442//clients/tokenrequestallowedipaddresses");
        //TODO Logged twice if scheduled task runs during the execution of this test.
        //assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN response: 404", "http.response.status_code=404, http.response.body.content=\"\"");
    }

    @Test
    void admin_TokenRequestAllowedIpAddressesRequestRespondsWithEmptyBody_EmptyResponseIsStoredInMapAndSavedToFile() throws IOException {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")));

        createTokenRequestAllowedIpAddressesFile();
        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        boolean isTokenRequestAllowed = tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-from-file", "1.1.1.1");
        Map<String, List<String>> tokenRequestAllowedIpAddressesFromFile = objectMapper.readValue(new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath()), new TypeReference<>() {
        });
        assertThat(tokenRequestAllowedIpAddressesFromFile.isEmpty(), is(true));
        assertThat(tokenRequestAllowedIpAddressesService.tokenRequestAllowedIpAddresses.isEmpty(), is(true));
        assertThat(isTokenRequestAllowed, is(false));
        assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN request", "http.request.method=GET, url.full=https://admin.localhost:17442//clients/tokenrequestallowedipaddresses");
        assertMessageWithMarkerIsLoggedOnce(TokenRequestAllowedIpAddressesService.class, INFO, "ADMIN response: 200", "http.response.status_code=200, http.response.body.content={}");
    }

    @Test
    void admin_AllowedIpAddressesMapIsSetFromFile_TokenRequestIsAllowed() throws IOException {
        createTokenRequestAllowedIpAddressesFile();

        tokenRequestAllowedIpAddressesService.loadIpAddressesFromFileIgnoringExceptions();

        boolean isTokenRequestAllowed = tokenRequestAllowedIpAddressesService.isTokenRequestAllowed("client-from-file", "1.1.1.1");
        assertThat(isTokenRequestAllowed, is(true));
        assertMessageIsNotLogged(TokenRequestAllowedIpAddressesService.class, "ADMIN request");
    }

    private void createTokenRequestAllowedIpAddressesFile() throws IOException {
        Map<String, List<String>> tokenRequestAllowedIpAddresses = new HashMap<>();
        tokenRequestAllowedIpAddresses.put("client-from-file", List.of("1.1.1.1"));
        objectMapper.writeValue(new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath()), tokenRequestAllowedIpAddresses);
    }
}
