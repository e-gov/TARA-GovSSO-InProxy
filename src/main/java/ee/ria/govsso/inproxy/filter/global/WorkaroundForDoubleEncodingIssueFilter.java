package ee.ria.govsso.inproxy.filter.global;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.BitSet;
import java.util.stream.Stream;

import static java.util.function.Predicate.not;
import static org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter.ROUTE_TO_URL_FILTER_ORDER;

// org.springframework.web.util.HierarchicalUriComponents does not allow unencoded = in query parameter value, which is
// stricter than RFC 3986. When Spring Cloud Gateway encounters such query parameter values, it assumes that all query
// parameters are unencoded and encodes all query parameters, which is incorrent
// (https://github.com/spring-cloud/spring-cloud-gateway/issues/2065). This filter is applied before Spring Cloud
// Gateway's query parameter logic and this filter ensures that query parameters are encoded according to stricter rules
// so that Spring Cloud Gateway's bug is not triggered.
@Component
public class WorkaroundForDoubleEncodingIssueFilter implements GlobalFilter, Ordered {

    public static final BitSet QUERY_PARAM_ALLOWED = new BitSet(256);
    private static final int RADIX = 16;

    static {
        /* See https://www.ietf.org/rfc/rfc3986.txt Appendix A */
        BitSet UNRESERVED = new BitSet(256);
        BitSet SUB_DELIMITERS = new BitSet(256);
        BitSet P_CHAR = new BitSet(256);
        for (int i = 'a'; i <= 'z'; i++) {
            UNRESERVED.set(i);
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            UNRESERVED.set(i);
        }
        for (int i = '0'; i <= '9'; i++) {
            UNRESERVED.set(i);
        }
        UNRESERVED.set('-');
        UNRESERVED.set('.');
        UNRESERVED.set('_');
        UNRESERVED.set('~');

        SUB_DELIMITERS.set('!');
        SUB_DELIMITERS.set('$');
        SUB_DELIMITERS.set('&');
        SUB_DELIMITERS.set('\'');
        SUB_DELIMITERS.set('(');
        SUB_DELIMITERS.set(')');
        SUB_DELIMITERS.set('*');
        SUB_DELIMITERS.set('+');
        SUB_DELIMITERS.set(',');
        SUB_DELIMITERS.set(';');
        SUB_DELIMITERS.set('=');

        P_CHAR.or(UNRESERVED);
        P_CHAR.or(SUB_DELIMITERS);
        P_CHAR.set(':');
        P_CHAR.set('@');
        // pct-encoded is omitted from P_CHAR and handled separately in `encodeUnencodedSymbols` method.

        // See `org.springframework.web.util.HierarchicalUriComponents.Type.QUERY_PARAM`
        QUERY_PARAM_ALLOWED.or(P_CHAR);
        QUERY_PARAM_ALLOWED.set('/');
        QUERY_PARAM_ALLOWED.set('?');
        QUERY_PARAM_ALLOWED.clear('=');
        QUERY_PARAM_ALLOWED.clear('&');
    }

    @Override
    public int getOrder() {
        return ROUTE_TO_URL_FILTER_ORDER + 1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        URI originalUri = exchange.getRequest().getURI();
        MultiValueMap<String, String> encodedQueryParams = parseRawQueryParams(originalUri.getRawQuery())
                .map(this::encodeUnencodedSymbols)
                .collect(LinkedMultiValueMap::new,
                        (multimap, input) -> multimap.add(input.getKey(), input.getValue()),
                        MultiValueMap::putAll);

        URI uri = UriComponentsBuilder.fromUri(originalUri).replaceQueryParams(encodedQueryParams).build(true).toUri();
        return chain.filter(exchange.mutate()
                .request(request -> request.uri(uri))
                .build());
    }

    private Stream<Pair<String, String>> parseRawQueryParams(String rawQuery) {
        String[] queryParams = StringUtils.split(rawQuery, "&");
        return Arrays.stream(queryParams)
                .filter(not(String::isEmpty))
                .map(queryParam -> {
                    String[] queryParamParts = StringUtils.splitPreserveAllTokens(queryParam, "=", 2);
                    String key = queryParamParts[0];
                    String value = queryParamParts.length > 1 ? queryParamParts[1] : null;
                    return Pair.of(key, value);
                });
    }

    private Pair<String, String> encodeUnencodedSymbols(Pair<String, String> queryParam) {
        return Pair.of(
                encodeUnencodedSymbols(queryParam.getKey()),
                queryParam.getValue() != null ? encodeUnencodedSymbols(queryParam.getValue()) : null);
    }

    // Adapted from `org.apache.hc.core5.net.PercentCodec.encode`.
    private String encodeUnencodedSymbols(String content) {
        StringBuilder result = new StringBuilder();
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(content));
        while (bb.hasRemaining()) {
            final int b = bb.get() & 0xff;
            if (QUERY_PARAM_ALLOWED.get(b)) {
                result.append((char) b);
            } else if (b == '%') {
                result.append((char) b);
                result.append((char) (bb.get() & 0xff));
                result.append((char) (bb.get() & 0xff));
            } else {
                result.append("%");
                final char hex1 = Character.toUpperCase(Character.forDigit((b >> 4) & 0xF, RADIX));
                final char hex2 = Character.toUpperCase(Character.forDigit(b & 0xF, RADIX));
                result.append(hex1);
                result.append(hex2);
            }
        }
        return result.toString();
    }


}
