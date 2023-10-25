package ee.ria.govsso.inproxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static io.restassured.RestAssured.given;

@ActiveProfiles({"tara"})
public class TaraHeartbeatEndpointTest extends BaseTest {

    @BeforeEach
    void setupTaraMocks() {
        // Return HTTP 200 OK for every URL path, except /notfound
        TARA_MOCK_SERVER.stubFor(get(urlPathMatching("^(?!.*\\/notfound).*$"))
                .willReturn(aResponse().withStatus(200)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/heartbeat", "/heartbeatpage", "/heartbeat/sub/path"})
    void tara_pathBeginsWithHeartbeat_Returns404(String path) {
        given()
                .when()
                .get(path)
                .then()
                .assertThat()
                .statusCode(404);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/otherurl", "/allowed/url/"})
    void tara_pathDoesNotBeginWithHeartbeat_PassesThrough(String path) {
        given()
                .when()
                .get(path)
                .then()
                .assertThat()
                .statusCode(200);
    }
}
