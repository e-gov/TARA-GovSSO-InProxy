package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"govsso"})
public class GovSsoHydraLoginEndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";
    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_CONSENT_VALUE = "consent";

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/oauth2/auth"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_requests_login.json")));
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

}
