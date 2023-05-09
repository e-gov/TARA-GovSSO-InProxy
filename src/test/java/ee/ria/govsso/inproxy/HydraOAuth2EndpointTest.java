package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

public class HydraOAuth2EndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";
    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_CONSENT_VALUE = "consent";
    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    @BeforeEach
    void setupHydraMocks() {
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
        HYDRA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/oauth2/auth/requests/login"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_requests_login.json")));
    }

    @Test
    // TODO GSSO-589: Split into 2 tests: one should have source IP in allowlist and the other one should not
    void hydra_oAuthToken_ReturnsToken() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_token.json");
        given()
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));
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
                .get("/oauth2/auth/requests/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/auth/requests/login?pRoMpT=someValue"))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithEmptyPromptParameter_AddsPromptParameterValue() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("pRoMpT", "")
                .when()
                .get("/oauth2/auth/requests/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo(String.format("/oauth2/auth/requests/login?pRoMpT=%s", PROMPT_PARAMETER_CONSENT_VALUE)))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithoutPromptParameter_AddsPromptParameterKeyAndValue() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .when()
                .get("/oauth2/auth/requests/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo(String.format("/oauth2/auth/requests/login?%s=%s", PROMPT_PARAMETER_NAME, PROMPT_PARAMETER_CONSENT_VALUE)))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

    @Test
    void hydra_oAuth2RequestsLoginWithTraceParentParameter_AddsHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_requests_login.json");
        given()
                .queryParam("proMpT", "someValue")
                .queryParam("tracePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/auth/requests/login")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/auth/requests/login"))
                        .withQueryParam("proMpT", equalTo("someValue"))
                        .withQueryParam("tracePaReNt", equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE))
                        .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_requestWithSensitiveHeader_PassesHeaderToHydra() {
        given()
                .header(AUTHORIZATION_HEADER_NAME, "value")
                .when()
                .get("/oauth2/token")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/token"))
                .withHeader(AUTHORIZATION_HEADER_NAME, equalTo("value")));
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
