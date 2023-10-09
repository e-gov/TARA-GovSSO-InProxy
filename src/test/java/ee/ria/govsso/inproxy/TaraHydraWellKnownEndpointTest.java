package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.util.TestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;
@ActiveProfiles({"tara"})
public class TaraHydraWellKnownEndpointTest extends BaseTest {

    @Test
    void hydra_openIdConfiguration_ReturnsConfiguration() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_openid-configuration.json")));
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_openid-configuration.json");
        given()
                .when()
                .get("/oidc/.well-known/openid-configuration")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));
    }

    @Test
    void hydra_jwks_ReturnsKeys() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/jwks.json"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_jwks.json")));
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_jwks.json");
        given()
                .when()
                .get("/oidc/jwks")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));
    }

    @Test
    void hydra_NotConfiguredEndpoint_Returns404() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/.well-known/restricted-endpoint"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_jwks.json")));
        given()
                .when()
                .get("/.well-known/restricted-endpoint")
                .then()
                .assertThat()
                .statusCode(404);
    }
}
