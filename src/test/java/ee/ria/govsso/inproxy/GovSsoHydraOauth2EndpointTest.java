package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import ee.ria.govsso.inproxy.util.TestUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;

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

@ActiveProfiles({"govsso"})
public class GovSsoHydraOauth2EndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";
    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_CONSENT_VALUE = "consent";
    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));
        HYDRA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/oauth2/sessions/logout"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_sessions_logout.json")));
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

        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("Authorization", "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
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
                .header("Authorization", "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.2.3.4")
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("unauthorized_client"))
                .body("error_description", Matchers.equalTo("Your IP address 1.2.3.4 is not whitelisted"));

        ADMIN_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    //TODO Add more tests for odd authorization header cases
    @ParameterizedTest
    @ValueSource(strings = {"Basic", ""})
    void hydra_oAuthTokenRequestIncorrectAuthorizationHeader_Returns400Error(String authorizationHeader) {

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("Authorization", authorizationHeader)
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("invalid_grant"))
                .body("error_description", Matchers.equalTo("The provided authorization grant is invalid."));

        ADMIN_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
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

        ADMIN_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @Test
    void hydra_oAuthTokenRequestIpInHeaderNotWhitelisted_Returns400Error() {

        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBody("{\"client-a\":[\"127.0.0.1\"]}")));

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        given()
                .when()
                .contentType("application/x-www-form-urlencoded; charset=utf-8")
                .header("Authorization", "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.1.1.1")
                .post("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(400)
                .header(HttpHeaders.CONTENT_TYPE, "application/json")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body("error", Matchers.equalTo("unauthorized_client"))
                .body("error_description", Matchers.equalTo("Your IP address 1.1.1.1 is not whitelisted"));

        ADMIN_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oauth2/token")));
    }

    @Test
    void hydra_oAuth2SessionsLogoutWithTraceParentParameter_AddsHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_sessions_logout.json");
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_oAuth2SessionsLogoutWithoutTraceParentParameter_DoesNotAddHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_sessions_logout.json");
        given()
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/sessions/logout"))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithPromptParameter_DoesNotModifyUrlParameters() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("pRoMpT", "someValue")
                .when()
                .get("/oauth2/auth")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/auth?pRoMpT=someValue"))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithEmptyPromptParameter_AddsPromptParameterValue() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("pRoMpT", "")
                .when()
                .get("/oauth2/auth")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo(String.format("/oauth2/auth?pRoMpT=%s", PROMPT_PARAMETER_CONSENT_VALUE)))
                        .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithoutPromptParameter_AddsPromptParameterKeyAndValue() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .when()
                .get("/oauth2/auth")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo(String.format("/oauth2/auth?%s=%s", PROMPT_PARAMETER_NAME, PROMPT_PARAMETER_CONSENT_VALUE)))
                        .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithTraceParentParameter_AddsHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("proMpT", "someValue")
                .queryParam("tracePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/auth")
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

        tokenRequestAllowedIpAddressesService.updateAllowedIpsTask();

        given()
                .header(AUTHORIZATION_HEADER_NAME, "Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")
                .header("X-Forwarded-For", "1.1.1.1")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/token"))
                .withHeader(AUTHORIZATION_HEADER_NAME, equalTo("Basic Y2xpZW50LWE6Z1gxZkJhdDNiVg==")));
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
}
