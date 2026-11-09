package ee.ria.govsso.inproxy.filter;

import ee.ria.govsso.inproxy.filter.EidUseXForwardedForFilter.TrustStrategy;
import ee.ria.govsso.inproxy.util.forwarded.ParsedXForwardedForUtil;
import org.assertj.core.api.AbstractAssert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.net.InetSocketAddress;
import java.util.List;

import static ee.ria.govsso.inproxy.filter.EidUseXForwardedForFilter.X_FORWARDED_FOR;
import static ee.ria.govsso.inproxy.filter.EidUseXForwardedForFilterTest.ServerWebExchangeAssert.assertThatExchange;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.header;
import static ee.ria.govsso.inproxy.util.HeaderTestUtil.headers;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

class EidUseXForwardedForFilterTest {

    private static final InetSocketAddress ORIGINAL_REMOTE_ADDRESS = new InetSocketAddress("10.255.8.1", 12345);
    private static final List<String> VALID_IPS = List.of(
            "2.2.2.2",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::2"
    );
    private static final List<String> INVALID_IPS = List.of(
            "",
            "example.com",
            "2.2.2.2:8080",
            "999.2.2.2",
            "2.2.2.0/24",
            "2.2.2.0/32",
            "2.2.2.2/32",
            "2.2.2.*",
            "2.2.2.1-5",
            "2001:db8::/32",
            "*",
            "\n"
    );

    private TrustStrategy trustStrategy = mock(TrustStrategy.class);
    private EidUseXForwardedForFilter filter = new EidUseXForwardedForFilter(trustStrategy);

    @AfterEach
    void tearDown() {
        reset(trustStrategy);
    }

    @Test
    void givenNoXffHeader_thenExchangeUnmodified() {
        ServerWebExchange originalExchange = exchange();
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        assertThatExchange(result).isEquivalentTo(originalExchange);
    }

    @Test
    void givenMultipleXffHeaders_thenExchangeUnmodified() {
        ServerWebExchange originalExchange = exchange(
                headers(
                        header(X_FORWARDED_FOR, "1.1.1.1"),
                        header(X_FORWARDED_FOR, "1.2.3.4")));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        assertThatExchange(result).isEquivalentTo(originalExchange);
    }

    @ParameterizedTest
    @FieldSource("VALID_IPS")
    void givenSingleHop_givenHopValid_thenRemoteIpUpdated_thenParsedXffValueSet(String validIp) {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, validIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        ServerWebExchange expected = originalExchange.mutate()
                .request(request -> request.remoteAddress(new InetSocketAddress(validIp, 0)))
                .build();
        ParsedXForwardedForUtil.set(expected, validIp);

        assertThatExchange(result).isEquivalentTo(expected);
    }

    @ParameterizedTest
    @FieldSource("INVALID_IPS")
    void givenSingleHop_givenHopInvalid_thenExchangeUnmodified(String invalidIp) {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, invalidIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        assertThatExchange(result).isEquivalentTo(originalExchange);
    }

    @ParameterizedTest
    @FieldSource("VALID_IPS")
    void givenMultipleHops_givenAllHopsValid_thenRemoteIpSetToLastHop_thenParsedXffValueSet(String validIp) {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, "1.1.1.1, " + validIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        ServerWebExchange expected = originalExchange.mutate()
                .request(request -> request.remoteAddress(new InetSocketAddress(validIp, 0)))
                .build();
        ParsedXForwardedForUtil.set(expected, validIp);

        assertThatExchange(result).isEquivalentTo(expected);
    }

    @ParameterizedTest
    @FieldSource("VALID_IPS")
    void givenMultipleHops_givenOnlyLastHopValid_thenRemoteIpSetToLastHop_thenParsedXffValueSet(String validIp) {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, "the-invalid-ip, " + validIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        ServerWebExchange expected = originalExchange.mutate()
                .request(request -> request.remoteAddress(new InetSocketAddress(validIp, 0)))
                .build();
        ParsedXForwardedForUtil.set(expected, validIp);

        assertThatExchange(result).isEquivalentTo(expected);
    }

    @ParameterizedTest
    @FieldSource("INVALID_IPS")
    void givenMultipleHops_givenLastHopInvalid_thenExchangeUnmodified(String invalidIp) {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, "1.1.1.1, " + invalidIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        assertThatExchange(result).isEquivalentTo(originalExchange);
    }

    @Test
    void givenValidSingleHop_givenRequestUntrusted_thenExchangeUnmodified() {
        ServerWebExchange originalExchange = exchange(header(X_FORWARDED_FOR, "1.1.1.1"));
        treatAsUntrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

        assertThatExchange(result).isEquivalentTo(originalExchange);
    }

    @Test
    void givenHeaderNameAllLowercase_givenValidSingleHop_thenRemoteIpUpdated_thenParsedXffValueSet() {
        String hopIp = "1.1.1.1";
        ServerWebExchange originalExchange = exchange(header("x-forwarded-for", hopIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

                ServerWebExchange expected = originalExchange.mutate()
                .request(request -> request.remoteAddress(new InetSocketAddress(hopIp, 0)))
                .build();
        ParsedXForwardedForUtil.set(expected, hopIp);
    }

    @Test
    void givenHeaderNameAllUppercase_givenValidSingleHop_thenRemoteIpUpdated_thenParsedXffValueSet() {
        String hopIp = "1.1.1.1";
        ServerWebExchange originalExchange = exchange(header("X-FORWARDED-FOR", hopIp));
        treatAsTrusted(originalExchange);

        ServerWebExchange result = doFilter(originalExchange);

                ServerWebExchange expected = originalExchange.mutate()
                .request(request -> request.remoteAddress(new InetSocketAddress(hopIp, 0)))
                .build();
        ParsedXForwardedForUtil.set(expected, hopIp);
    }

    // As the currently available `TrustStrategy` implementations are trivial, complete test suits aren't required,
    // but a sanity-check is implemented.
    @Nested
    class TrustStrategyTest {

        @Test
        void givenTrustStrategyNever_thenEveryRequestUntrusted() {
            ServerWebExchange exchange = exchange();

            boolean actual = TrustStrategy.never().shouldTrust(exchange.getRequest());

            assertThat(actual).isEqualTo(false);
        }

        @Test
        void givenTrustStrategyAlways_thenEveryRequestTrusted() {

            ServerWebExchange exchange = exchange();

            boolean actual = TrustStrategy.always().shouldTrust(exchange.getRequest());

            assertThat(actual).isEqualTo(true);
        }

    }

    private ServerWebExchange doFilter(ServerWebExchange originalExchange) {
        MockFilterChain mockFilterChain = new MockFilterChain();
        filter.filter(originalExchange, mockFilterChain).block();
        return mockFilterChain.getCapturedExchange();
    }

    private void treatAsTrusted(ServerWebExchange exchange) {
        doReturn(true).when(trustStrategy).shouldTrust(exchange.getRequest());
    }

    private void treatAsUntrusted(ServerWebExchange exchange) {
        doReturn(false).when(trustStrategy).shouldTrust(exchange.getRequest());
    }

    private ServerWebExchange exchange() {
        return exchange(new HttpHeaders());
    }

    private ServerWebExchange exchange(HttpHeaders providedHeaders) {
        HttpHeaders unrelatedHeader = header("Unrelated", "this header should not be modified by the filter");
        HttpHeaders allHeaders = headers(providedHeaders, unrelatedHeader);
        return MockServerWebExchange.from(
                MockServerHttpRequest.get("/")
                        .headers(allHeaders)
                        .remoteAddress(ORIGINAL_REMOTE_ADDRESS));
    }



    public static class ServerWebExchangeAssert extends AbstractAssert<ServerWebExchangeAssert, ServerWebExchange> {

        private ServerWebExchangeAssert(ServerWebExchange actual) {
            super(actual, ServerWebExchangeAssert.class);
        }

        public static ServerWebExchangeAssert assertThatExchange(ServerWebExchange actual) {
            return new ServerWebExchangeAssert(actual);
        }

        @SuppressWarnings("UnusedReturnValue")
        public ServerWebExchangeAssert isEquivalentTo(ServerWebExchange expected) {
            assertThat(actual).usingRecursiveComparison().isEqualTo(expected);
            return this;
        }

    }

}
