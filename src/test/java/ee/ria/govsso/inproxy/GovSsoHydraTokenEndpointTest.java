package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.filter.IpAddressGatewayFilterFactory;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import ee.ria.govsso.inproxy.util.TestUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"govsso"})
public class GovSsoHydraTokenEndpointTest extends BaseTest {

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.2.3.4", "1.2.3.*", "1.2.3.0-100\", \"111.11.11.11"})
    void hydra_oAuthTokenRequestIpIsInAllowedIps_ReturnsToken(String whitelistedIps) {

        String responseBody = String.format("{\"client-a\":[\"%s\"]}", whitelistedIps);

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(responseBody)));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.2.3.4")
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1.2.3.5-100\", \"111.11.11.11", "1.2.3.2"})
    void hydra_oAuthTokenRequestIpNotInAllowedIps_Returns400Error(String whitelistedIps) {

        String responseBody = String.format("{\"client-a\":[\"%s\"]}", whitelistedIps);

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(responseBody)));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.2.3.4")
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("unauthorized_client"))
                .body("error_description", Matchers.equalTo("IP address 1.2.3.4 is not whitelisted for client_id \"client-a\""));

        HYDRA_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @Nested
    @TestPropertySource(properties = "tara-govsso-inproxy.token-request-block-ip-addresses=false")
    class IpBlockNotEnabledTests extends BaseTest {

        @BeforeEach
        void setupServerMocks() {
            GovSsoHydraTokenEndpointTest.this.setupServerMocks();
        }

        @ParameterizedTest
        @ValueSource(strings = {"1.2.3.5-100\", \"111.11.11.11", "1.2.3.2"})
        void hydra_oAuthTokenRequestIpNotInAllowedIps_Returns200_AndLogError(String whitelistedIps) {

            String responseBody = String.format("{\"client-a\":[\"%s\"]}", whitelistedIps);

            ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                    .willReturn(aResponse()
                            .withStatus(200)
                            .withHeader("Content-Type", "application/json; charset=UTF-8")
                            .withBody(responseBody)));

            tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

            given()
                    .when()
                    .contentType("application/x-www-form-urlencoded; charset=utf-8")
                    .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                    .header("X-Forwarded-For", "1.2.3.4")
                    .post("/oauth2/token")
                    .then()
                    .assertThat()
                    .statusCode(200);

            assertWarningIsLogged(IpAddressGatewayFilterFactory.class, "unauthorized_client - IP address 1.2.3.4 is not whitelisted for client_id \"client-a\", allowing request");
            HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));
        }

    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic", "Basic ", "Basic ThisIsNotAProperBase64String!", ""})
    void hydra_oAuthTokenRequestIncorrectAuthorizationHeader_Returns400Error(String authorizationHeader) {

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("invalid_grant"))
                .body("error_description", Matchers.equalTo("The provided authorization grant is invalid."));

        HYDRA_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @Test
    void hydra_oAuthTokenRequestMissingAuthorizationHeader_Returns400Error() {

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"client-a\":[\"127.0.0.1\"]}")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("X-Forwarded-For", "1.2.3.4")
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("invalid_grant"))
                .body("error_description", Matchers.equalTo("The provided authorization grant is invalid."));

        HYDRA_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id=client-a", "code=i1WsRn1uB1&client_id=client-a"})
    void hydra_oAuthTokenRequestWithSameClientIdInHeaderAndBody_Returns200(String requestBody) {

        String responseBody = String.format("{\"client-a\":[\"%s\"]}", "1.2.3.4");

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(responseBody)));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("X-Forwarded-For", "1.2.3.4")
                .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .body(requestBody)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id=client-b", "code=i1WsRn1uB1&client_id=client-b"})
    void hydra_oAuthTokenRequestWithDifferentClientIdInHeaderAndBody_Returns400Error(String requestBody) {

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("X-Forwarded-For", "1.2.3.4")
                .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .body(requestBody)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .body("error", Matchers.equalTo("invalid_grant"))
                .body("error_description", Matchers.equalTo("The provided authorization grant is invalid."));

    }

    @ParameterizedTest
    @ValueSource(strings = {"client_id=client-a", "code=i1WsRn1uB1&client_id=client-a"})
    void hydra_oAuthTokenRequestCorrectClientSecretPost_Returns200(String requestBody) {

        String responseBody = String.format("{\"client-a\":[\"%s\"]}", "1.2.3.4");

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody(responseBody)));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("X-Forwarded-For", "1.2.3.4")
                .body(requestBody)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "%="})
    void hydra_oAuthTokenRequestIncorrectClientSecretPost_Returns400Error(String requestBody) {

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .body(requestBody)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("invalid_grant"))
                .body("error_description", Matchers.equalTo("The provided authorization grant is invalid."));

        HYDRA_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

}
