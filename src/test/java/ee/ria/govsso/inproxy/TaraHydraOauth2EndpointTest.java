package ee.ria.govsso.inproxy;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ee.ria.govsso.inproxy.filter.IpAddressGatewayFilterFactory;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import ee.ria.govsso.inproxy.util.TestUtils;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;


@ActiveProfiles({"tara"})
class TaraHydraOauth2EndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/oauth2/auth"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_requests_login.json")));
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
                .post("/oidc/token")
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
                .post("/oidc/token")
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
            TaraHydraOauth2EndpointTest.this.setupServerMocks();
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
                    .post("/oidc/token")
                    .then()
                    .assertThat()
                    .statusCode(200);

            assertWarningIsLogged(IpAddressGatewayFilterFactory.class, "unauthorized_client - IP address 1.2.3.4 is not whitelisted for client_id \"client-a\", allowing request");
            HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));
        }

        @Test
        void hydra_oAuthTokenRequestHasEmptyXClientIdHeaderAndCorrectAccessLog_Returns400() {
            String responseBody = String.format("{\"client-a\":[\"%s\"]}", "1.2.3.4");

            ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json; charset=UTF-8")
                    .withBody(responseBody)));

            tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

            given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("X-Forwarded-For", "1.2.3.4")
                .header("X-ClientId", "client-b") // accesslog should have client-a
                .post("/oidc/token")
                .then()
                .assertThat()
                .statusCode(400);

            List<ILoggingEvent> logEntries = assertAccessLogIsLogged("-"); // checks if accesslog contains this string
            assertCorrectAccessLogFormat(logEntries, "-");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Basic", "Basic ", ""})
    void hydra_oAuthTokenRequestIncorrectAuthorizationHeader_Returns400Error(String authorizationHeader) {

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header(HttpHeaders.AUTHORIZATION, authorizationHeader)
                .post("/oidc/token")
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
                .post("/oidc/token")
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
                .post("/oidc/token")
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
                .post("/oidc/token")
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
                .post("/oidc/token")
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
                .post("/oidc/token")
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
    void hydra_oAuth2RequestsLoginWithTraceParentParameter_AddsHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("proMpT", "someValue")
                .queryParam("tracePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oidc/authorize")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/auth"))
                .withQueryParam("proMpT", equalTo("someValue"))
                .withQueryParam("tracePaReNt", equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

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
                .get("/oidc/token")
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
                .get("/oidc/authorize");

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/auth?state=FG6kE8S5SaU1%3D&redirect_uri=https://clienta.localhost:11443/login/oauth2/code/govsso")));
    }

    @Test
    void hydra_oAuthTokenRequestHasXClientIdHeaderAddedFromBodyValue_Returns200() {
        String requestBody = "client_id=client-a";
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
            .post("/oidc/token")
            .then()
            .assertThat()
            .statusCode(200)
            .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));

        List<ILoggingEvent> logEntries = assertAccessLogIsLogged("client-a"); // checks if accesslog contains this string
        assertCorrectAccessLogFormat(logEntries, "client-a");
    }

    @Test
    void hydra_oAuthTokenRequestHasXClientIdHeaderAddedFromHeaderValue_Returns200() {
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBody("{\"client-a\":[\"1.2.3.4\"]}")));

        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/token"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json; charset=UTF-8")
                .withBodyFile("mock_responses/hydra_token.json")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
            .header(HttpHeaders.AUTHORIZATION, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
            .when()
            .contentType("application/x-www-form-urlencoded; charset=utf-8")
            .header("X-Forwarded-For", "1.2.3.4")
            .post("/oidc/token")
            .then()
            .assertThat()
            .statusCode(200)
            .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));

        List<ILoggingEvent> logEntries = assertAccessLogIsLogged("client-a"); // checks if accesslog contains this string
        assertCorrectAccessLogFormat(logEntries,"client-a");
    }

    @Test
    void hydra_oAuthTokenRequestHasXClientIdHeaderAddedFromActualClientId_Returns200() {
        String requestBody = "client_id=client-a";
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
            .header("X-ClientId", "client-b") // accesslog should have client-a
            .body(requestBody)
            .post("/oidc/token")
            .then()
            .assertThat()
            .statusCode(200)
            .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));

        List<ILoggingEvent> logEntries = assertAccessLogIsLogged("client-a"); // checks if accesslog contains this string
        assertCorrectAccessLogFormat(logEntries, "client-a");
    }

    @Nested
    @TestPropertySource(properties = "tara-govsso-inproxy.enable-access-log=false")
    class AccessLogDisabledTests extends BaseTest {

        @Autowired
        private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

        @BeforeEach
        void setupServerMocks() {
            TaraHydraOauth2EndpointTest.this.setupServerMocks();
        }

        @Test
        void hydra_oAuthTokenRequestHasXClientIdHeaderAddedAccessLogDisabled_Returns200() {
            String requestBody = "client_id=client-a";
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
                .header("X-ClientId", "client-a")
                .body(requestBody)
                .post("/oidc/token")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

            HYDRA_MOCK_SERVER.verify(exactly(1), postRequestedFor(urlEqualTo("/oauth2/token")));

            assertAccessLogMessageIsNotLogged("client-a");
        }
    }
}
