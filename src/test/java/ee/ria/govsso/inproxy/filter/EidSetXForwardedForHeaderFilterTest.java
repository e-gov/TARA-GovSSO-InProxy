package ee.ria.govsso.inproxy.filter;

import ee.ria.govsso.inproxy.util.forwarded.ParsedXForwardedForUtil;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.net.InetSocketAddress;

import static ee.ria.govsso.inproxy.filter.EidSetXForwardedForHeaderFilter.X_FORWARDED_FOR;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.header;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.headers;
import static org.assertj.core.api.Assertions.assertThat;

class EidSetXForwardedForHeaderFilterTest {

    private static final String REMOTE_IP = "10.255.8.1";
    private static final HttpHeaders UNRELATED_HEADER =
            header("Unrelated", "this header should not be modified by the filter");

    private final MockExchangeFactory exchangeFactory = new MockExchangeFactory();

    @Test
    public void givenHeaderDoesNotExist_givenNoParsedXffValue_givenAppendDisabled_thenHeadersUnchanged() {
        MockServerWebExchange exchange = exchangeFactory.withoutParsedXffValue();
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(false);

        HttpHeaders result = filter.filter(UNRELATED_HEADER, exchange);

        assertThat(result).isEqualTo(UNRELATED_HEADER);
    }

    @Test
    public void givenHeaderOriginallyExisted_givenNoParsedXffValue_givenAppendDisabled_thenHeaderRemoved() {
        MockServerWebExchange exchange = exchangeFactory.withoutParsedXffValue();
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(false);
        HttpHeaders inputHeaders = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1"));

        HttpHeaders result = filter.filter(inputHeaders, exchange);

        assertThat(result).isEqualTo(UNRELATED_HEADER);
    }

    @Test
    public void givenHeaderDoesNotExist_givenNoParsedXffValue_givenAppendEnabled_thenHeaderSetToRemoteIp() {
        MockServerWebExchange exchange = exchangeFactory.withoutParsedXffValue();
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(true);

        HttpHeaders result = filter.filter(UNRELATED_HEADER, exchange);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenHeaderOriginallyExisted_givenNoParsedXffValue_givenAppendEnabled_thenHeaderSetToRemoteIp() {
        MockServerWebExchange exchange = exchangeFactory.withoutParsedXffValue();
        HttpHeaders inputHeaders = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1"));
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(true);

        HttpHeaders result = filter.filter(inputHeaders, exchange);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenParsedXffValue_givenAppendDisabled_thenHeaderSetToConcatenatedValue() {
        MockServerWebExchange exchange = exchangeFactory.withParsedXffValue("1.1.1.1, 2.2.2.2");
        HttpHeaders headers = UNRELATED_HEADER;
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(false);
        HttpHeaders result = filter.filter(headers, exchange);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1, 2.2.2.2"));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenParsedXffValue_givenAppendEnabled_thenHeaderSetToForwardedChainAndRemoteIpConcatenated() {
        MockServerWebExchange exchange = exchangeFactory.withParsedXffValue("1.1.1.1, 2.2.2.2");

        HttpHeaders headers = UNRELATED_HEADER;
        EidSetXForwardedForHeaderFilter filter = new EidSetXForwardedForHeaderFilter(true);
        HttpHeaders result = filter.filter(headers, exchange);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1, 2.2.2.2, " + REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    private static class MockExchangeFactory {

        private @NonNull MockServerWebExchange withParsedXffValue(String value) {
            MockServerWebExchange exchange = withoutParsedXffValue();
            ParsedXForwardedForUtil.set(exchange, value);
            return exchange;
        }

        private @NonNull MockServerWebExchange withoutParsedXffValue() {
            return MockServerWebExchange.from(
                    MockServerHttpRequest.get("/")
                            .header("exchange headers are unused", "the filter should not access the headers of the exchange")
                            .remoteAddress(new InetSocketAddress(REMOTE_IP, 12345)));
        }

    }

}
