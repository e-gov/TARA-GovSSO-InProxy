package ee.ria.govsso.inproxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static io.restassured.RestAssured.given;
@ActiveProfiles({"govsso"})
public class GovSsoAdminEndpointTest extends BaseTest {

    @BeforeEach
    void setupAdminMocks() {
        // Return HTTP 200 OK for every URL path, except /notfound
        SESSION_MOCK_SERVER.stubFor(get(urlPathMatching("^(?!.*\\/notfound).*$"))
                .willReturn(aResponse().withStatus(200)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/admin", "/adminpage", "/admin/sub/path"})
    void admin_pathBeginsWithAdmin_Returns404(String path) {
        given()
                .when()
                .get(path)
                .then()
                .assertThat()
                .statusCode(404);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/otherurl", "/allowed/url/"})
    void admin_pathDoesNotBeginWithAdmin_PassesThrough(String path) {
        given()
                .when()
                .get(path)
                .then()
                .assertThat()
                .statusCode(200);
    }
}
