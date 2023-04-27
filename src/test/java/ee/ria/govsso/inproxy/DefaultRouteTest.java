package ee.ria.govsso.inproxy;

import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;

public class DefaultRouteTest extends BaseTest{

    private static final String HEADER_TRACEPARENT = "traceparent";
    private static final String HEADER_TRACESTATE = "tracestate";
    private static final String HEADER_ELASTIC_APM_TRACEPARENT = "elastic-apm-traceparent";

    @Test
    void defaultRoute_IncludesRestrictedHeaders_RemovesRestrictedHeaders() {
        SESSION_MOCK_SERVER.stubFor(get(urlEqualTo("/mock-path"))
                .willReturn(aResponse().withStatus(200)));

        given()
                .header(HEADER_TRACEPARENT, "value1")
                .header(HEADER_TRACESTATE, "value2")
                .header(HEADER_ELASTIC_APM_TRACEPARENT, "value3")
                .header("customHeader", "custom value")
                .header("user-agent", "Mozilla/5.0")
                .when()
                .get("/mock-path")
                .then()
                .assertThat()
                .statusCode(200);

        SESSION_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/mock-path"))
                .withoutHeader(HEADER_TRACEPARENT)
                .withoutHeader(HEADER_TRACESTATE)
                .withoutHeader(HEADER_ELASTIC_APM_TRACEPARENT)
                .withHeader("customHeader", WireMock.equalTo("custom value"))
                .withHeader("user-agent", WireMock.equalTo("Mozilla/5.0")));
    }
}
