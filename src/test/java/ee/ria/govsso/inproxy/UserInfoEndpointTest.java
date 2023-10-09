package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.exactly;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"tara"})
public class UserInfoEndpointTest extends BaseTest {

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_userinfo.json")));
    }

    @Test
    void oidcProfilePath_RewritesPathToUserinfo() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_userinfo.json");

        given()
                .when()
                .get("/oidc/profile")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(exactly(0), postRequestedFor(urlEqualTo("/oidc/profile")));
    }
}
