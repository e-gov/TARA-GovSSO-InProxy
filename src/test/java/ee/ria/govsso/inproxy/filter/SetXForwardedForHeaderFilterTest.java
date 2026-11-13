package ee.ria.govsso.inproxy.filter;

import ee.ria.govsso.inproxy.util.forwarded.ForwardedChainResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.util.List;

import static ee.ria.govsso.inproxy.filter.SetXForwardedForHeaderFilter.X_FORWARDED_FOR;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.header;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.headers;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class SetXForwardedForHeaderFilterTest {

    private static final String REMOTE_IP = "10.255.8.1";
    private static final HttpHeaders UNRELATED_HEADER =
            header("Unrelated", "this header should not be modified by the filter");
    private static final MockServerWebExchange EXCHANGE = MockServerWebExchange.from(
            MockServerHttpRequest.get("/")
                    .header("exchange headers are unused", "the filter should not access the headers of the exchange")
                    .remoteAddress(new InetSocketAddress(REMOTE_IP, 12345)));


    @Test
    public void givenHeaderDoesNotExist_givenEmptyForwardedChain_givenAppendDisabled_thenHeadersUnchanged() {
        SetXForwardedForHeaderFilter filter = new SetXForwardedForHeaderFilter(
                false,
                createMockForwardedChainResolver(EXCHANGE, List.of()));

        HttpHeaders result = filter.filter(UNRELATED_HEADER, EXCHANGE);

        assertThat(result).isEqualTo(UNRELATED_HEADER);
    }

    @Test
    public void givenHeaderOriginallyExisted_givenEmptyForwardedChain_givenAppendDisabled_thenHeaderRemoved() {

        SetXForwardedForHeaderFilter filter = new SetXForwardedForHeaderFilter(
                false,
                createMockForwardedChainResolver(EXCHANGE, List.of()));
        HttpHeaders inputHeaders = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1"));

        HttpHeaders result = filter.filter(inputHeaders, EXCHANGE);

        assertThat(result).isEqualTo(UNRELATED_HEADER);
    }

    @Test
    public void givenHeaderDoesNotExist_givenEmptyForwardedChain_givenAppendEnabled_thenHeaderSetToRemoteIp() {
        SetXForwardedForHeaderFilter filter = new SetXForwardedForHeaderFilter(
                true,
                createMockForwardedChainResolver(EXCHANGE, List.of()));

        HttpHeaders result = filter.filter(UNRELATED_HEADER, EXCHANGE);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenHeaderOriginallyExisted_givenEmptyForwardedChain_givenAppendEnabled_thenHeaderSetToRemoteIp() {
        HttpHeaders inputHeaders = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1"));
        SetXForwardedForHeaderFilter filter = new SetXForwardedForHeaderFilter(
                true,
                createMockForwardedChainResolver(EXCHANGE, List.of()));

        HttpHeaders result = filter.filter(inputHeaders, EXCHANGE);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenSingleForwardedValue_givenAppendDisabled_thenHeaderSetToTheForwardedValue() {

        SetXForwardedForHeaderFilter filter = new SetXForwardedForHeaderFilter(
                false,
                createMockForwardedChainResolver(EXCHANGE, List.of("1.1.1.1")));
        HttpHeaders result = filter.filter(UNRELATED_HEADER, EXCHANGE);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1"));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenMultipleForwardedValues_givenAppendDisabled_thenHeaderSetToConcatenatedValue() {
        ForwardedChainResolver forwardedChainResolver =
                createMockForwardedChainResolver(EXCHANGE, List.of("1.1.1.1", "2.2.2.2"));

        HttpHeaders headers = UNRELATED_HEADER;
        SetXForwardedForHeaderFilter filter =
                new SetXForwardedForHeaderFilter(false, forwardedChainResolver);
        HttpHeaders result = filter.filter(headers, EXCHANGE);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1, 2.2.2.2"));
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void givenMultipleForwardedValues_givenAppendEnabled_thenHeaderSetToForwardedChainAndRemoteIpConcatenated() {
        ForwardedChainResolver forwardedChainResolver =
                createMockForwardedChainResolver(EXCHANGE, List.of("1.1.1.1", "2.2.2.2"));

        HttpHeaders headers = UNRELATED_HEADER;
        SetXForwardedForHeaderFilter filter =
                new SetXForwardedForHeaderFilter(true, forwardedChainResolver);
        HttpHeaders result = filter.filter(headers, EXCHANGE);

        HttpHeaders expected = headers(
                UNRELATED_HEADER,
                header(X_FORWARDED_FOR, "1.1.1.1, 2.2.2.2, " + REMOTE_IP));
        assertThat(result).isEqualTo(expected);
    }

    private ForwardedChainResolver createMockForwardedChainResolver(ServerWebExchange exchange, List<String> hops) {
        ForwardedChainResolver mock = mock(ForwardedChainResolver.class);
        doReturn(hops).when(mock).resolve(exchange.getRequest());
        return mock;
    }

}
