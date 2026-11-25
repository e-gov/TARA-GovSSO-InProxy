package ee.ria.govsso.inproxy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static io.restassured.RestAssured.given;
import static org.springframework.http.HttpStatus.OK;

@ActiveProfiles({"govsso"})
public class XForwardedRelayTest extends BaseTest {

    @BeforeEach
    void setUp() {
        SESSION_MOCK_SERVER.stubFor(any(anyUrl())
                .willReturn(aResponse().withStatus(OK.value())));
    }

    @Test
    void anyRoute_XForwardedForHeaderPresent_HeaderRelayed() {
        String forwardedIp = "1.2.3.4";
        given()
                .header("X-Forwarded-For", forwardedIp)
                .get("/path");
        SESSION_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo("/path"))
                        .withHeader("X-Forwarded-For", equalTo(forwardedIp)));
    }

    @Test
    void anyRoute_XForwardedForHeaderHasMultipleIps_HeaderRelayed() {
        String forwardedIp = "1.2.3.4, 5.6.7.8, 2001:db8:85a3:8d3:1319:8a2e:370:7348";
        given()
                .header("X-Forwarded-For", forwardedIp)
                .get("/path");
        SESSION_MOCK_SERVER.verify(
                getRequestedFor(urlEqualTo("/path"))
                        .withHeader("X-Forwarded-For", equalTo(forwardedIp)));
    }
}
