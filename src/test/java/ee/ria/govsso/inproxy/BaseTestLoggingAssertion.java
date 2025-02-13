package ee.ria.govsso.inproxy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.regex.Pattern;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;

public class BaseTestLoggingAssertion {

    private static ListAppender<ILoggingEvent> mockLogAppender;
    private ListAppender<ILoggingEvent> accessLogAppender;
    private static final String ACCESS_LOGGER_NAME = "reactor.netty.http.server.AccessLog";


    @BeforeEach
    public void addMockLogAppender() {
        // Attach root logger appender (for application logs)
        mockLogAppender = new ListAppender<>();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockLogAppender);
        mockLogAppender.start();

        // Attach AccessLog appender (for Netty access logs)
        accessLogAppender = new ListAppender<>();
        ((Logger) getLogger(ACCESS_LOGGER_NAME)).addAppender(accessLogAppender);
        accessLogAppender.start();
    }

    @AfterEach
    public void afterEachTest() {
        List<ILoggingEvent> unmatchedErrorsAndWarnings = mockLogAppender.list.stream()
                .filter(e -> e.getLevel() == ERROR || e.getLevel() == WARN)
                .collect(Collectors.toList());

        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockLogAppender);
        ((Logger) getLogger(ACCESS_LOGGER_NAME)).detachAppender(accessLogAppender);

        assertThat(unmatchedErrorsAndWarnings, empty());
    }

    protected List<ILoggingEvent> assertInfoIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, INFO, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, WARN, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, ERROR, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertInfoIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, INFO, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, WARN, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(Class<?> loggerClass, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, ERROR, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertMessageIsLogged(Predicate<ILoggingEvent> additionalFilter, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(null, null, additionalFilter, messagesInRelativeOrder);
    }

    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, String... messagesInRelativeOrder) {
        return assertMessageIsLogged(loggerClass, loggingLevel, null, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertAccessLogIsLogged(String... messagesInRelativeOrder) {
        return assertAccessLogMessageIsLogged(messagesInRelativeOrder);
    }

    private List<ILoggingEvent> assertAccessLogMessageIsLogged(String... messagesInRelativeOrder) {
        List<String> expectedMessages = of(messagesInRelativeOrder);
        Stream<ILoggingEvent> eventStream = accessLogAppender.list.stream()
            .filter(e -> expectedMessages.stream().anyMatch(expected -> e.getFormattedMessage().contains(expected)));
        List<ILoggingEvent> events = eventStream.collect(toList());
        accessLogAppender.list.removeAll(events);
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).collect(toList());
        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + of(messagesInRelativeOrder) + ",\n\tActual log messages: " + messages,
            messages, containsInRelativeOrder(expectedMessages.stream().map(CoreMatchers::containsString).toArray(Matcher[]::new)));
        return events;
    }

    @SuppressWarnings("unchecked")
    private List<ILoggingEvent> assertMessageIsLogged(Class<?> loggerClass, Level loggingLevel, Predicate<ILoggingEvent> additionalFilter, String... messagesInRelativeOrder) {
        List<String> expectedMessages = of(messagesInRelativeOrder);
        Stream<ILoggingEvent> eventStream = mockLogAppender.list.stream()
                .filter(e -> loggingLevel == null || e.getLevel() == loggingLevel)
                .filter(e -> loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName()))
                .filter(e -> expectedMessages.stream().anyMatch(expected -> e.getFormattedMessage().startsWith(expected)));
        if (additionalFilter != null) {
            eventStream = eventStream.filter(additionalFilter);
        }
        List<ILoggingEvent> events = eventStream.collect(toList());
        mockLogAppender.list.removeAll(events);
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).collect(toList());
        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + of(messagesInRelativeOrder) + ",\n\tActual log messages: " + messages,
                messages, containsInRelativeOrder(expectedMessages.stream().map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
        return events;
    }

    protected void assertAccessLogMessageIsNotLogged(String message) {
        String loggedMessage = accessLogAppender.list.stream()
            .map(ILoggingEvent::getFormattedMessage)
            .filter(msg -> msg.contains(message))
            .findFirst()
            .orElse(null);
        assertNull(loggedMessage);
    }

    protected void assertMessageIsNotLogged(Class<?> loggerClass, String message) {
        String loggedMessage = mockLogAppender.list.stream()
                .filter(e -> (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())))
                .map(ILoggingEvent::getFormattedMessage)
                .filter(msg -> msg.equals(message))
                .findFirst()
                .orElse(null);
        assertNull(loggedMessage);
    }

    protected void assertMessageWithMarkerIsLoggedOnce(Class<?> loggerClass, Level loggingLevel, String message, String expectedMarket) {
        List<ILoggingEvent> matchingLoggingEvents = mockLogAppender.list.stream()
                .filter(e -> e.getLevel() == loggingLevel &&
                        (loggerClass == null || e.getLoggerName().equals(loggerClass.getCanonicalName())) &&
                        e.getFormattedMessage().equals(message))
                .filter(e -> e.getMarker().toString().startsWith(expectedMarket))
                .collect(toList());
        mockLogAppender.list.removeAll(matchingLoggingEvents);
        assertNotNull(matchingLoggingEvents);
        assertThat(matchingLoggingEvents, hasSize(1));
    }

    protected void assertCorrectAccessLogFormat(List<ILoggingEvent> logEntries, String expectedClientId) {
        assertFalse(logEntries.isEmpty(), "No accesslog entries found");

        for (ILoggingEvent logEntry : logEntries) {
            String formattedMessage = logEntry.getFormattedMessage();
            // Sample expected format:
            // /127.0.0.1:54933 - client-a [2025-02-13T14:41:33.642177+02:00[Europe/Tallinn]] "POST /oidc/token HTTP/1.1" 200 711 102

            String logPattern = "^(.+?) - (.+?) \\[(.+?)] \"(.+?) (.+?) (.+?)\" (\\d+) (\\d+|-) (\\d+)$";
            Pattern pattern = Pattern.compile(logPattern);
            var matcher = pattern.matcher(formattedMessage);

            assertTrue(matcher.matches(), "Access log format does not match expected pattern");

            String ipAddress = matcher.group(1);
            String clientId = matcher.group(2);
            String timestamp = matcher.group(3);
            String httpMethod = matcher.group(4);
            String uri = matcher.group(5);
            String protocol = matcher.group(6);
            String statusCode = matcher.group(7);
            String contentLength = matcher.group(8);
            String duration = matcher.group(9);

            assertTrue(ipAddress.matches("/.+?:\\d+"), "IP format is incorrect: " + ipAddress);
            assertEquals(expectedClientId, clientId, "Client name does not match: " + clientId);
            assertTrue(timestamp.matches(".+"), "Timestamp format is incorrect: " + timestamp);
            assertTrue(httpMethod.matches("[A-Z]+"), "HTTP method format is incorrect: " + httpMethod);
            assertTrue(uri.matches("/.+"), "URI format is incorrect: " + uri);
            assertTrue(protocol.matches("HTTP/\\d\\.\\d"), "Protocol format is incorrect: " + protocol);
            assertTrue(statusCode.matches("\\d{3}"), "Status code format is incorrect: " + statusCode);
            assertTrue(contentLength.matches("\\d+|-"), "Content length format is incorrect: " + contentLength);
            assertTrue(duration.matches("\\d+"), "Duration format is incorrect: " + duration);
        }
    }
}
