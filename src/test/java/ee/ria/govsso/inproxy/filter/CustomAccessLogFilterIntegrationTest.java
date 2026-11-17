package ee.ria.govsso.inproxy.filter;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import ee.ria.govsso.inproxy.BaseTest;
import io.restassured.RestAssured;
import io.restassured.config.DecoderConfig;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.convention.TestBean;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.slf4j.LoggerFactory.getLogger;
import static org.springframework.http.HttpStatus.OK;

@ActiveProfiles({"govsso"})
class CustomAccessLogFilterIntegrationTest extends BaseTest {

    private ListAppender<ILoggingEvent> accessLogAppender;

    @TestBean
    Clock clock;

    static Clock clock() {
        return Clock.fixed(Instant.parse("2026-11-16T12:00:00Z"), ZoneId.of("Europe/Tallinn"));
    }

    @BeforeEach
    void setUp() {
        SESSION_MOCK_SERVER.stubFor(any(anyUrl())
                .willReturn(aResponse().withStatus(OK.value())));

        accessLogAppender = new ListAppender<>();
        getAccessLogger().addAppender(accessLogAppender);
        accessLogAppender.start();
    }

    @AfterEach
    void tearDown() {
        getAccessLogger().detachAppender(accessLogAppender);
    }

    // FIXME: Wrong IP asserted
    @Test
    void anyRoute_givenMultipleXForwardedForValues_thenLastValueUsed() {
        ValidatableResponse response = given()
                // Remove decoders to access the real response size
                .config(RestAssured.config().decoderConfig(DecoderConfig.decoderConfig().noContentDecoders()))
                .queryParam("key", "value")
                .header("X-Forwarded-For", "4.4.4.4, 5.5.5.5")
                .header("Accept-Encoding", "gzip,deflate")
                .when()
                .get("/any-path")
                .then()
                .assertThat()
                .statusCode(200);
        int responseSize = response.extract().asByteArray().length;

        List<ILoggingEvent> loggingEvents = accessLogAppender.list;
        assertThat(loggingEvents).hasSize(1);
        ILoggingEvent loggingEvent = loggingEvents.get(0);
        String message = loggingEvent.getFormattedMessage();
        assertThat(message).isEqualTo(
                "%s - - [%s] \"GET /any-path HTTP/1.1\" 200 %d 0".formatted(
                        "127.0.0.1",
                        "2026-11-16T14:00:00+02:00[Europe/Tallinn]",
                        responseSize
                )
        );
    }

    private static Logger getAccessLogger() {
        return (Logger) getLogger(CustomAccessLogFilter.class);
    }

}
