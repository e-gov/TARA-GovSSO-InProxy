package ee.ria.govsso.inproxy;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import ee.ria.govsso.inproxy.util.TestUtils;
import lombok.SneakyThrows;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.function.Consumer;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static ee.ria.govsso.inproxy.util.JwtUtil.generateTestRsaKeyPair;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"govsso"})
public class GovSsoHydraLogoutEndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";
    public static final String ID_TOKEN_WITH_REPRESENTEE_LIST = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjdoOFNnWGRfWUt2WVIzZzFJZ0xtbkEiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTU5NCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjQ5NCwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNTk0LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiIwMDI3M2E3OS00ZWVkLTQxZTItOGI3Yy1jYTQ5Njk5NDQxMzgiLCJub25jZSI6InZGdmhRWE8yYUVGWVhLZFlyLVFqRExLYVh5VGc0QlBOeG1VSTl6RmNwSTgiLCJyYXQiOjE3NDEyNTE1MDksInJlcHJlc2VudGVlX2xpc3QiOnsibGlzdCI6W10sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJhYjQyMzY3ZS0xOTdjLTQxMTQtYjlkNC1lNDAwMjAwZmFkYmMiLCJzdWIiOiJFRTQwNTA0MDQwMDAxIn0.ACVVhigl_n2XkvmEd4NvDo-n-Jtm_opw5ATUoonr78yxh5nF311-Xs2sfVx81x7t6hlZDQBEAMLQSmaACFWOGyY7j71y9nuqq72DeQM99O-rOEhrQD3PhvMaPDRrRwokZEZcjVRX3dN3-b9-DeykQn0mjUEcZ-CslztlnF1V2lDtoP_ny7qPgUjYuFKnZCXq9-2lG1uCZo7YGpDPwuZl4ld6DiM_DJDsnjJjbiWRYdGshFGlGDfHeV3sWbGl8OemD-xZyEIyw95taNPLZi3-kgUuQr9eXSXyLFRxPGUkNiSWL-02WcEPoTw-tepNrNxS9c0y0nh3gXHCK3lsEj2oxm9PF9d_qxzhdRJ-sG3-IPEg40fTxB0BPsiLzi7bj-EXBxBitSLtCyVDOIl6OFh28psG2fA8Eh3s2Mu9u2Gk-xkDUNnT1WX1RW5BH-yv79-_yygU-h1X-qjxja_0JYkYloSudf0mqhLSskVSKpSg0K40ouw-tjB5eryt5iOi0k4QzaqHax8iHRnyIw1tiNNWLE7kUQrEGQeVcuZ6wG5NVA6pfmU4HCQxagfMMDJ0dfrthVNrDDfVRkOkSZ7pmr3MpWTEUoIAOvPZUIxopSvx2tghh-jPv5MHXXPdFCHK-QxBp91eNhnA_IbDwedZRrXG8dnuDJ6anR4j9R5Uem8tOTY";
    public static final String ID_TOKEN_WITHOUT_REPRESENTEE_LIST = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNkZjQ2OGYwLWVlNGUtNGE3Yy1iMTQ1LTNjNjFhYTg1NjliNyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IjlIYTMxZkhxR01nbmI4WkZod1VpZ1EiLCJhdWQiOlsiZWYxN2E1NDUtOGJmOS00OTc4LTgxNDUtNjA0MDk5NzkwMGFjIl0sImF1dGhfdGltZSI6MTc0MTI1MTY5OCwiYmlydGhkYXRlIjoiMTkwNS0wNC0wNCIsImV4cCI6MTc0MTI1MjU5OSwiZmFtaWx5X25hbWUiOiJURVNUTlVNQkVSIiwiZ2l2ZW5fbmFtZSI6Ik9LIiwiaWF0IjoxNzQxMjUxNjk5LCJpc3MiOiJodHRwczovL2dvdnNzby1kZW1vLnJpYS5lZS8iLCJqdGkiOiI5NmExNTZmNy04YTBmLTQ5MzUtYWZlNy1hYTBlM2M4YTkzMWIiLCJub25jZSI6ImluTGVyUWJmdlBwaFlpYXAzNEZQR0VuTnAwQ0dIajJxZUJmUDNoQ2ozWXciLCJyYXQiOjE3NDEyNTE2ODUsInNpZCI6ImJmMGRkOWI3LTg3MmUtNDFhNi1iOWZhLWJiYWRhNGZkMjc3ZiIsInN1YiI6IkVFNDA1MDQwNDAwMDEifQ.MJWVeL_bQhcd8MTOe1Qo90cbEpB879TT0p1IBeuzdEn5cnlG6r2M8bXRddhQQDXjufdncngZEfhgbtP1dQaLx45ATEhatIwJfpVZbr0qz0pMvCb8MgoqyR4b2T9h5438RXPuKCZdmvVdmpomrx5hbiLZExUmF-AnoXiT-H9JYePCwqu4Enom7WChys9UT48v1i3_P09pJU3KA-Of_t3KucssP0bQ03GEZipLFhjNMCKK1A2kXzvLUNweEIwf7HP9hzejUO1dqaPs8cdr6lpFSKUIVoMSgWp5l3mCeCn6uKvgODdfKCnJKYqv7oe6ozwQ4i13v2RFqDGWoQNQXTDlTvlOY1vZOYbgGjf-Qpe9gCfScFivGpYMAWMPXoTXllQ-gKxg4fDq6P44yQ1htXuNM1EwyEdREFAa-iGoe-pVPBQ7ygRViCDhwL6zgLjkC88B0A7dI73VAtIKIWQ_mnnTj6eMFlIgiKcLDhfkOA0egNsc5caF_kshJ2wQo2Fb1_-FaXr0C2MZaHvy1PmA2GBEExSSQheq871IMxI4bPq0HbcXr1gdbXU6fcapT9O0fAiBsXogUwHHqJacymWyoXVieKvA-NJDQZSnq5mHZo0kP6eJUz4DuWwTnK-qJrreUlLFsCJRdGaR2BSiJcin7abEHPOXUgH3akahh7puGBtarHs";

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(any(urlPathEqualTo("/oauth2/sessions/logout"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_sessions_logout.json")));
    }

    @Test
    void hydra_logoutPostRequestQueryParamIdTokenHintContainingRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", ID_TOKEN_WITH_REPRESENTEE_LIST)
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=The%20%27id_token_hint%27%20query%20parameter%20is%20not%20allowed%20when%20using%20logout%20request%20with%20http%20POST%20method%2C%20it%20must%20be%20passed%20as%20a%20form%20parameter")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_logoutPostRequestFormParamIdTokenHintContainingRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .formParam("id_token_hint", ID_TOKEN_WITH_REPRESENTEE_LIST)
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(postRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_logoutGetRequestWithRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", ID_TOKEN_WITH_REPRESENTEE_LIST)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=Logout%20request%20must%20use%20POST%20method%20if%20the%20id%20token%20from%20%27id_token_hint%27%20parameter%20contains%20a%20%27representee_list%27%20claim")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_logoutGetRequestWithRepresenteeListFromSpecialClientApplication_isSuccessful() {
        String jwtString = createTestJwt(
                ID_TOKEN_WITH_REPRESENTEE_LIST,
                claims -> claims.audience("special-backwards-compatibility-logout-client"));
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", jwtString)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void hydra_logoutGetRequestWithoutRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", ID_TOKEN_WITHOUT_REPRESENTEE_LIST)
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
    void hydra_logoutGetRequestWithInvalidIdTokenHint_isRedirectedToErrorPage(String idToken) {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", idToken)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=The%20%27id_token_hint%27%20query%20parameter%20value%20is%20not%20a%20valid%20JWS")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_logoutGetRequestWithMultipleIdTokenHints_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", ID_TOKEN_WITH_REPRESENTEE_LIST)
                .queryParam("id_token_hint", ID_TOKEN_WITHOUT_REPRESENTEE_LIST)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=Multiple%20%27id_token_hint%27%20query%20parameters%20found")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_logoutGetRequestNoAudienceInIdTokenHints_serverErrorReturned() {
        String jwtString = createTestJwt(
                ID_TOKEN_WITH_REPRESENTEE_LIST,
                claims -> claims.audience((List<String>) null));
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", jwtString)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(500);
        //TODO: Can not look for a more specific log message as it starts with randomly generated string.
        assertErrorIsLogged("");
    }


    @Test
    void hydra_logoutGetRequestMultipleAudienceValuesInIdTokenHints_serverErrorReturned() {
        String jwtString = createTestJwt(
                ID_TOKEN_WITH_REPRESENTEE_LIST,
                claims -> claims.audience(List.of("client-1", "client-2")));
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", jwtString)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(500);
        //TODO: Can not look for a more specific log message as it starts with randomly generated string.
        assertErrorIsLogged("");
    }

    @Test
    void hydra_logoutGetRequestWithMissingIdTokenHint_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void hydra_logoutWithTraceParentParameter_AddsHeader() {
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
    void hydra_logoutWithoutTraceParentParameter_DoesNotAddHeader() {
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

    @SneakyThrows
    private static String createTestJwt(String baseJwtString, Consumer<JWTClaimsSet.Builder> func) {
        SignedJWT originalJwt = SignedJWT.parse(baseJwtString);
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder(originalJwt.getJWTClaimsSet());
        func.accept(claimsBuilder);
        JWTClaimsSet claims = claimsBuilder.build();
        JWSObject jwt = new JWSObject(originalJwt.getHeader(), claims.toPayload());
        jwt.sign(new RSASSASigner(generateTestRsaKeyPair()));
        return jwt.serialize();
    }

}
