package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;

import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static java.nio.charset.StandardCharsets.UTF_8;

@ActiveProfiles({"govsso"})
public class GovSsoHydraEndpointsTest extends BaseTest {

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @Test
    void hydra_requestWithSensitiveHeader_PassesHeaderToHydra() {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"client-a\":[\"1.1.1.1\"]}")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        given()
                .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.1.1.1")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/token"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")));
    }

    @Test
    void hydra_urlParametersContainSpecialCharacters_DoesNotEncodeValues() {
        given()
                // Rest Assured URL-encodes the query (i.e. "%3D" would be converted to "%253D"), unless we explicitly disable it.
                .urlEncodingEnabled(false)
                .queryParam("state", "FG6kE8S5SaU1%3D")
                .queryParam("redirect_uri", "https://clienta.localhost:11443/login/oauth2/code/govsso")
                .when()
                .get("/oauth2/auth");

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/auth?state=FG6kE8S5SaU1%3D&redirect_uri=https://clienta.localhost:11443/login/oauth2/code/govsso&prompt=consent")));
    }

    @Test
    void hydra_clientIdContainsEncodedCharacters_ItIsProperlyDecoded() {
        String clientId = "Client ä: (x+y=z)";
        // Spaces (" ") can be encoded as either plus sign ("+") or "%20", so lets use both options
        String clientIdXWwwFormUrlEncoded = "Client+%C3%A4%3A%20%28x%2By%3Dz%29";
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"" + clientId + "\":[\"1.1.1.1\"]}")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String clientIdSecretPair = clientIdXWwwFormUrlEncoded + ":ignored-secret";
        String authorization = new String(Base64.getEncoder().encode(clientIdSecretPair.getBytes(UTF_8)), UTF_8);

        given()
                .header(HttpHeaders.AUTHORIZATION, "Basic " + authorization)
                .header("X-Forwarded-For", "1.1.1.1")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/token"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Basic " + authorization)));
    }

    @Test
    void hydra_clientIdContainsCharactersThatShouldBeEncodedButDoNotHaveOtherMeaning_TheseCharactersAreKept() {
        String clientId = "Client ä%25: (x+y=z)";
        // Plus symbol ("+") MUST be encoded, otherwise it would be decoded to space (" ").
        // Colon (":") MUST be encoded as it is used as a separator between client ID and client secret.
        // Percent sign ("%") MUST be encoded as it is used as the start of an escape sequence.
        String clientIdXWwwFormUrlEncoded = "Client ä%2525%3A (x%2By=z)";
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"" + clientId + "\":[\"1.1.1.1\"]}")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String clientIdSecretPair = clientIdXWwwFormUrlEncoded + ":ignored-secret";
        String authorization = new String(Base64.getEncoder().encode(clientIdSecretPair.getBytes(UTF_8)), UTF_8);

        given()
                .header(HttpHeaders.AUTHORIZATION, "Basic " + authorization)
                .header("X-Forwarded-For", "1.1.1.1")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/token"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Basic " + authorization)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Client:A", "Client+A", "Client%A"})
    void hydra_clientIdContainsCharactersThatMustBeEncoded_ErrorReturned(String clientId) {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"" + clientId + "\":[\"1.1.1.1\"]}")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String clientIdSecretPair = clientId + ":ignored-secret";
        String authorization = new String(Base64.getEncoder().encode(clientIdSecretPair.getBytes(UTF_8)), UTF_8);

        given()
                .header(HttpHeaders.AUTHORIZATION, "Basic " + authorization)
                .header("X-Forwarded-For", "1.1.1.1")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400);

        HYDRA_MOCK_SERVER.verify(exactly(0), getRequestedFor(urlPathEqualTo("/oauth2/token")));
    }
}
