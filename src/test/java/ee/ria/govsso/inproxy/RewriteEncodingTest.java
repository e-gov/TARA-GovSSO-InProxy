package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.filter.global.WorkaroundForDoubleEncodingIssueFilter;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static ee.ria.govsso.inproxy.RewriteEncodingTest.SimpleUriBuilder.simpleUri;
import static io.restassured.RestAssured.with;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.http.HttpStatus.OK;

@ActiveProfiles({"govsso"})
public class RewriteEncodingTest extends BaseTest {

    private static final int RADIX = 16;

    @BeforeEach
    void setUp() {
        SESSION_MOCK_SERVER.stubFor(any(anyUrl())
                .willReturn(aResponse().withStatus(OK.value())));
    }

    @Nested
    class QueryParamsTest {

        @Test
        void anyRoute_UnencodedEqualsSign_QueryParamsAreNotDoubleEncoded() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key%43", "value%43")
                            .queryParam("otherKey%43", "otherValue==")
                            .build());
            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(
                    simpleUri().path("/path")
                            .queryParam("key%43", "value%43")
                            .queryParam("otherKey%43", "otherValue%3D%3D")
                            .build())));
        }

        @Test
        void anyRoute_OnlyEncodedSymbols_QueryParamsAreNotModified() {
            String uri = simpleUri().path("/path")
                    .queryParam("%6B%65%79", "%76%61%6C%7565")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        void anyRoute_ParameterWithMultipleValues_AllValuesAreRetained() {
            String key = "key%43";
            String uri = simpleUri().path("/path")
                    .queryParam(key, "value%43")
                    .queryParam(key, "otherValue%43")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        void anyRoute_ParameterWithoutValue_ParameterIsRetained() {
            with()
                    .urlEncodingEnabled(false)
                    .get("/path?foo");

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/path?foo")));
        }

        @Test
        void anyRoute_ParameterWithEmptyValue_AllValuesAreRetained() {
            String uri = "/path?key=";
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        @Disabled("Building URI fails")
        void anyRoute_IllegalEscapeSequence_ErrorReturned() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key%XX", "value")
                            .build())
                    .then()
                    .statusCode(400);
        }

        @Test
        @Disabled("Building URI fails")
        void anyRoute_IncompleteEscapeSequenceInKey_ErrorReturned() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key%5", "value")
                            .build())
                    .then()
                    .statusCode(400);
        }

        @Test
        @Disabled("Building URI fails")
        void anyRoute_IncompleteEscapeSequenceInValue_ErrorReturned() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key", "value%5")
                            .build())
                    .then()
                    .statusCode(400);
        }


        @Test
        @Disabled("Building URI fails")
        void anyRoute_TrailingPercentSign_ErrorReturned() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key", "value%")
                            .build())
                    .then()
                    .statusCode(400);
        }

        @Test
        void anyRoute_EncodedHighestValue_QueryParamsAreNotModified() {
            String uri = simpleUri().path("/path")
                    .queryParam("key%FF", "value")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        void anyRoute_EncodedLowestValue_QueryParamsAreNotModified() {
            String uri = simpleUri().path("/path")
                    .queryParam("key%00key", "value")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        @Disabled("Sending request fails")
        void anyRoute_OnlyEqualsSymbols_ErrorReturned() {
            String uri = "/path?======";
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        @Disabled("Query param value is omitted before it reaches Netty request handler")
        void anyRoute_OnlyEqualsSymbolsInValue_SymbolsAreEncoded() {
            String uri = simpleUri().path("/path")
                    .queryParam("key", "======")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        @Disabled("Building URI fails")
        void anyRoute_OnlySymbolsRequiringEncoding_SymbolsAreEncoded() {
            StringBuilder unencodedBuilder = new StringBuilder();
            StringBuilder encodedBuilder = new StringBuilder();
            for (int i = 0x20; i < 0x7F; i++) {
                if (WorkaroundForDoubleEncodingIssueFilter.QUERY_PARAM_ALLOWED.get(i)) {
                    continue;
                }
                unencodedBuilder.append((char) i);
                encodedBuilder.append('%');
                encodedBuilder.append(Character.toUpperCase(Character.forDigit((i >> 4) & 0xF, RADIX)));
                encodedBuilder.append(Character.toUpperCase(Character.forDigit(i & 0xF, RADIX)));
            }
            String unencodedValue = unencodedBuilder.toString();
            String encodedValue = encodedBuilder.toString();
            String unencodedKey = unencodedValue.replace("=", "");
            String encodedKey = encodedValue.replace("%3D", "");

            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam(unencodedKey, unencodedValue)
                            .build());

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(
                    simpleUri().path("/path")
                            .queryParam(encodedKey, encodedValue)
                            .build())));
        }

        @Test
        @Disabled("Symbols are encoded before reaching filter")
        void anyRoute_UnencodedMultibyteUtf8Symbol_SymbolIsEncoded() {
            with()
                    .urlEncodingEnabled(false)
                    .get(simpleUri().path("/path")
                            .queryParam("key", "ä")
                            .build());

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(
                    simpleUri().path("/path")
                            .queryParam("key", "%C3%A4")
                            .build())));
        }

        @Test
        void anyRoute_EncodedMultibyteUtf8Symbol_QueryParamsAreNotModified() {
            String uri = simpleUri().path("/path")
                    .queryParam("key", "%C3%A4")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

        @Test
        @Disabled
        void anyRoute_UnencodedMultibyteUtf16Symbol_SymbolIsEncoded() {
            // FIXME(AUT-1803): Implement
            fail();
        }

        @Test
        @Disabled
        void anyRoute_EncodedMultibyteUtf16Symbol_QueryParamsAreNotModified() {
            // FIXME(AUT-1803): Implement
            fail();
        }

        @Test
        void anyRoute_EncodedValuesDoNotDecodeToValidUtf8Symbol_QueryParamsAreNotModified() {
            String uri = simpleUri().path("/path")
                    .queryParam("key", "%A4%C3")
                    .build();
            with()
                    .urlEncodingEnabled(false)
                    .get(uri);

            SESSION_MOCK_SERVER.verify(getRequestedFor(urlEqualTo(uri)));
        }

    }

    /**
     * A very basic URI concatenating tool that used to increase readability
     */
    static class SimpleUriBuilder {

        private String path = "/";
        private List<Pair<String, String>> queryParams = new ArrayList<>();

        public static SimpleUriBuilder simpleUri() {
            return new SimpleUriBuilder();
        }

        public SimpleUriBuilder path(String path) {
            this.path = path;
            return this;
        }

        public SimpleUriBuilder queryParam(String key, String value) {
            this.queryParams.add(Pair.of(key, value));
            return this;
        }

        public String build() {
            String query = queryParams.stream()
                    .map(param -> param.getKey() + "=" + param.getValue())
                    .collect(Collectors.joining("&"));
            return path + "?" + query;
        }

    }

}
