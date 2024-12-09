package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.filter.IpAddressGatewayFilterFactory;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import ee.ria.govsso.inproxy.util.TestUtils;
import io.restassured.response.ExtractableResponse;
import io.restassured.response.Response;
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

import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"govsso"})
public class GovSsoHydraOauth2EndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";
    private static final String PROMPT_PARAMETER_NAME = "prompt";
    private static final String PROMPT_PARAMETER_CONSENT_VALUE = "consent";

    @Autowired
    private TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(post(urlEqualTo("/oauth2/token"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_token.json")));
        HYDRA_MOCK_SERVER.stubFor(any(urlPathEqualTo("/oauth2/sessions/logout"))
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
            GovSsoHydraOauth2EndpointTest.this.setupServerMocks();
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

    @Test
    void hydra_oAuth2SessionsLogoutPostRequestQueryParamIdTokenHintContainingRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjdoOFNnWGRfWUt2WVIzZzFJZ0xtbkEiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTU5NCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjQ5NCwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNTk0LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiIwMDI3M2E3OS00ZWVkLTQxZTItOGI3Yy1jYTQ5Njk5NDQxMzgiLCJub25jZSI6InZGdmhRWE8yYUVGWVhLZFlyLVFqRExLYVh5VGc0QlBOeG1VSTl6RmNwSTgiLCJyYXQiOjE3NDEyNTE1MDksInJlcHJlc2VudGVlX2xpc3QiOnsibGlzdCI6W10sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJhYjQyMzY3ZS0xOTdjLTQxMTQtYjlkNC1lNDAwMjAwZmFkYmMiLCJzdWIiOiJFRTQwNTA0MDQwMDAxIn0.ACVVhigl_n2XkvmEd4NvDo-n-Jtm_opw5ATUoonr78yxh5nF311-Xs2sfVx81x7t6hlZDQBEAMLQSmaACFWOGyY7j71y9nuqq72DeQM99O-rOEhrQD3PhvMaPDRrRwokZEZcjVRX3dN3-b9-DeykQn0mjUEcZ-CslztlnF1V2lDtoP_ny7qPgUjYuFKnZCXq9-2lG1uCZo7YGpDPwuZl4ld6DiM_DJDsnjJjbiWRYdGshFGlGDfHeV3sWbGl8OemD-xZyEIyw95taNPLZi3-kgUuQr9eXSXyLFRxPGUkNiSWL-02WcEPoTw-tepNrNxS9c0y0nh3gXHCK3lsEj2oxm9PF9d_qxzhdRJ-sG3-IPEg40fTxB0BPsiLzi7bj-EXBxBitSLtCyVDOIl6OFh28psG2fA8Eh3s2Mu9u2Gk-xkDUNnT1WX1RW5BH-yv79-_yygU-h1X-qjxja_0JYkYloSudf0mqhLSskVSKpSg0K40ouw-tjB5eryt5iOi0k4QzaqHax8iHRnyIw1tiNNWLE7kUQrEGQeVcuZ6wG5NVA6pfmU4HCQxagfMMDJ0dfrthVNrDDfVRkOkSZ7pmr3MpWTEUoIAOvPZUIxopSvx2tghh-jPv5MHXXPdFCHK-QxBp91eNhnA_IbDwedZRrXG8dnuDJ6anR4j9R5Uem8tOTY")
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=The+%27id_token_hint%27+query+parameter+is+not+allowed+when+using+logout+request+with+http+POST+method%2C+it+must+be+passed+as+a+form+parameter")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_oAuth2SessionsLogoutPostRequestFormParamIdTokenHintContainingRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .formParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjdoOFNnWGRfWUt2WVIzZzFJZ0xtbkEiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTU5NCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjQ5NCwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNTk0LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiIwMDI3M2E3OS00ZWVkLTQxZTItOGI3Yy1jYTQ5Njk5NDQxMzgiLCJub25jZSI6InZGdmhRWE8yYUVGWVhLZFlyLVFqRExLYVh5VGc0QlBOeG1VSTl6RmNwSTgiLCJyYXQiOjE3NDEyNTE1MDksInJlcHJlc2VudGVlX2xpc3QiOnsibGlzdCI6W10sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJhYjQyMzY3ZS0xOTdjLTQxMTQtYjlkNC1lNDAwMjAwZmFkYmMiLCJzdWIiOiJFRTQwNTA0MDQwMDAxIn0.ACVVhigl_n2XkvmEd4NvDo-n-Jtm_opw5ATUoonr78yxh5nF311-Xs2sfVx81x7t6hlZDQBEAMLQSmaACFWOGyY7j71y9nuqq72DeQM99O-rOEhrQD3PhvMaPDRrRwokZEZcjVRX3dN3-b9-DeykQn0mjUEcZ-CslztlnF1V2lDtoP_ny7qPgUjYuFKnZCXq9-2lG1uCZo7YGpDPwuZl4ld6DiM_DJDsnjJjbiWRYdGshFGlGDfHeV3sWbGl8OemD-xZyEIyw95taNPLZi3-kgUuQr9eXSXyLFRxPGUkNiSWL-02WcEPoTw-tepNrNxS9c0y0nh3gXHCK3lsEj2oxm9PF9d_qxzhdRJ-sG3-IPEg40fTxB0BPsiLzi7bj-EXBxBitSLtCyVDOIl6OFh28psG2fA8Eh3s2Mu9u2Gk-xkDUNnT1WX1RW5BH-yv79-_yygU-h1X-qjxja_0JYkYloSudf0mqhLSskVSKpSg0K40ouw-tjB5eryt5iOi0k4QzaqHax8iHRnyIw1tiNNWLE7kUQrEGQeVcuZ6wG5NVA6pfmU4HCQxagfMMDJ0dfrthVNrDDfVRkOkSZ7pmr3MpWTEUoIAOvPZUIxopSvx2tghh-jPv5MHXXPdFCHK-QxBp91eNhnA_IbDwedZRrXG8dnuDJ6anR4j9R5Uem8tOTY")
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(postRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjdoOFNnWGRfWUt2WVIzZzFJZ0xtbkEiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTU5NCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjQ5NCwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNTk0LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiIwMDI3M2E3OS00ZWVkLTQxZTItOGI3Yy1jYTQ5Njk5NDQxMzgiLCJub25jZSI6InZGdmhRWE8yYUVGWVhLZFlyLVFqRExLYVh5VGc0QlBOeG1VSTl6RmNwSTgiLCJyYXQiOjE3NDEyNTE1MDksInJlcHJlc2VudGVlX2xpc3QiOnsibGlzdCI6W10sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJhYjQyMzY3ZS0xOTdjLTQxMTQtYjlkNC1lNDAwMjAwZmFkYmMiLCJzdWIiOiJFRTQwNTA0MDQwMDAxIn0.ACVVhigl_n2XkvmEd4NvDo-n-Jtm_opw5ATUoonr78yxh5nF311-Xs2sfVx81x7t6hlZDQBEAMLQSmaACFWOGyY7j71y9nuqq72DeQM99O-rOEhrQD3PhvMaPDRrRwokZEZcjVRX3dN3-b9-DeykQn0mjUEcZ-CslztlnF1V2lDtoP_ny7qPgUjYuFKnZCXq9-2lG1uCZo7YGpDPwuZl4ld6DiM_DJDsnjJjbiWRYdGshFGlGDfHeV3sWbGl8OemD-xZyEIyw95taNPLZi3-kgUuQr9eXSXyLFRxPGUkNiSWL-02WcEPoTw-tepNrNxS9c0y0nh3gXHCK3lsEj2oxm9PF9d_qxzhdRJ-sG3-IPEg40fTxB0BPsiLzi7bj-EXBxBitSLtCyVDOIl6OFh28psG2fA8Eh3s2Mu9u2Gk-xkDUNnT1WX1RW5BH-yv79-_yygU-h1X-qjxja_0JYkYloSudf0mqhLSskVSKpSg0K40ouw-tjB5eryt5iOi0k4QzaqHax8iHRnyIw1tiNNWLE7kUQrEGQeVcuZ6wG5NVA6pfmU4HCQxagfMMDJ0dfrthVNrDDfVRkOkSZ7pmr3MpWTEUoIAOvPZUIxopSvx2tghh-jPv5MHXXPdFCHK-QxBp91eNhnA_IbDwedZRrXG8dnuDJ6anR4j9R5Uem8tOTY")
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=Logout+request+must+use+POST+method+if+the+id+token+from+%27id_token_hint%27+parameter+contains+a+%27representee_list%27+claim")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithoutRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjlIYTMxZkhxR01nbmI4WkZod1VpZ1EiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTY5OCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjU5OSwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNjk5LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiI5NmExNTZmNy04YTBmLTQ5MzUtYWZlNy1hYTBlM2M4YTkzMWIiLCJub25jZSI6ImluTGVyUWJmdlBwaFlpYXAzNEZQR0VuTnAwQ0dIajJxZUJmUDNoQ2ozWXciLCJyYXQiOjE3NDEyNTE2ODUsInNpZCI6ImJmMGRkOWI3LTg3MmUtNDFhNi1iOWZhLWJiYWRhNGZkMjc3ZiIsInN1YiI6IkVFNDA1MDQwNDAwMDEifQ.MJWVeL_bQhcd8MTOe1Qo90cbEpB879TT0p1IBeuzdEn5cnlG6r2M8bXRddhQQDXjufdncngZEfhgbtP1dQaLx45ATEhatIwJfpVZbr0qz0pMvCb8MgoqyR4b2T9h5438RXPuKCZdmvVdmpomrx5hbiLZExUmF-AnoXiT-H9JYePCwqu4Enom7WChys9UT48v1i3_P09pJU3KA-Of_t3KucssP0bQ03GEZipLFhjNMCKK1A2kXzvLUNweEIwf7HP9hzejUO1dqaPs8cdr6lpFSKUIVoMSgWp5l3mCeCn6uKvgODdfKCnJKYqv7oe6ozwQ4i13v2RFqDGWoQNQXTDlTvlOY1vZOYbgGjf-Qpe9gCfScFivGpYMAWMPXoTXllQ-gKxg4fDq6P44yQ1htXuNM1EwyEdREFAa-iGoe-pVPBQ7ygRViCDhwL6zgLjkC88B0A7dI73VAtIKIWQ_mnnTj6eMFlIgiKcLDhfkOA0egNsc5caF_kshJ2wQo2Fb1_-FaXr0C2MZaHvy1PmA2GBEExSSQheq871IMxI4bPq0HbcXr1gdbXU6fcapT9O0fAiBsXogUwHHqJacymWyoXVieKvA-NJDQZSnq5mHZo0kP6eJUz4DuWwTnK-qJrreUlLFsCJRdGaR2BSiJcin7abEHPOXUgH3akahh7puGBtarHs")
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "abcdefg", "abcdefg.12345"})
    void hydra_oAuth2SessionsLogoutGetRequestWithInvalidIdTokenHint_isSuccessful(String idToken) {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", idToken)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithMissingIdTokenHint_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
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
