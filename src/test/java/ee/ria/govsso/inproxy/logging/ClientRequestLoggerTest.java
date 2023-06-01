package ee.ria.govsso.inproxy.logging;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ee.ria.govsso.inproxy.BaseTestLoggingAssertion;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;

import java.util.List;

import static ee.ria.govsso.inproxy.logging.ClientRequestLogger.Service.ADMIN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

@Slf4j
class ClientRequestLoggerTest extends BaseTestLoggingAssertion {

    private final ClientRequestLogger clientRequestLogger = new ClientRequestLogger(ADMIN, ClientRequestLogger.class);

    @Test
    void logRequest_WhenNoRequestBody() {
        clientRequestLogger.logRequest("https://admin.localhost:17442", HttpMethod.GET);
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "ADMIN request");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat(logEvent.getMarker().toString(), equalTo(
                "http.request.method=GET, url.full=https://admin.localhost:17442"));
    }

    @Test
    void logRequest_WhenRequestBodyPresent() {
        clientRequestLogger.logRequest("https://admin.localhost:17442", HttpMethod.GET, "RequestBody");
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "ADMIN request");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat(logEvent.getMarker().toString(), equalTo(
                "http.request.method=GET, url.full=https://admin.localhost:17442, http.request.body.content=\"RequestBody\""));
    }

    @Test
    void logResponse_WhenNoResponseBody() {
        clientRequestLogger.logResponse(HttpStatus.OK.value());
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "ADMIN response");
        assertThat(loggedEvents, hasSize(1));
        assertThat(loggedEvents.get(0).getMarker().toString(), equalTo("http.response.status_code=200"));
    }

    @Test
    void logResponse_WhenResponseBodyPresent() {
        clientRequestLogger.logResponse(HttpStatus.OK.value(), "ResponseBody");
        List<ILoggingEvent> loggedEvents = assertInfoIsLogged(ClientRequestLogger.class, "ADMIN response");
        assertThat(loggedEvents, hasSize(1));
        ILoggingEvent logEvent = loggedEvents.get(0);
        assertThat(logEvent.getMarker().toString(),
                equalTo("http.response.status_code=200, http.response.body.content=\"ResponseBody\""));
    }
}
