package ee.ria.govsso.inproxy.util.forwarded;

import lombok.experimental.UtilityClass;
import org.springframework.web.server.ServerWebExchange;

@UtilityClass
public class ParsedXForwardedForUtil {

    public static final String PARSED_XFF_VALUE_ATTR = ParsedXForwardedForUtil.class + ".parsedXffValue";

    public static void set(ServerWebExchange exchange, String value) {
        exchange.getAttributes().put(PARSED_XFF_VALUE_ATTR, value);
    }

    public static String get(ServerWebExchange exchange) {
        return exchange.getAttribute(PARSED_XFF_VALUE_ATTR);
    }

}
