package ee.ria.govsso.inproxy;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.unit.DataSize;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;

@ActiveProfiles({"govsso"})
public class GovSsoLongUrlTest extends BaseTest {

    @Test
    void anyHydraRoute_urlLengthAlmost128Kb_requestHandledSuccessfully() {
        String longParamName = "longParam";
        String longParamValue = "a".repeat((int) DataSize.ofKilobytes(127).toBytes());
        HYDRA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/oauth2/sessions/logout"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_sessions_logout.json")));

        given()
                .queryParam(longParamName, longParamValue)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withQueryParam(longParamName, equalTo(longParamValue)));
    }

}
