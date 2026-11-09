package ee.ria.govsso.inproxy.util;

import lombok.experimental.UtilityClass;
import org.springframework.http.HttpHeaders;

import java.util.Map;

import static java.util.Map.entry;

@UtilityClass
public class HeaderTestUtil {

    public static HttpHeaders header(String name, String value) {
        return headers(entry(name, value));
    }

    @SafeVarargs
    public static HttpHeaders headers(Map.Entry<String, String>... headerEntries) {
        HttpHeaders headers = new HttpHeaders();
        for (Map.Entry<String, String> headerEntry : headerEntries) {
            headers.add(headerEntry.getKey(), headerEntry.getValue());
        }
        return headers;
    }

    public static HttpHeaders headers(HttpHeaders... headerses) {
        HttpHeaders result = new HttpHeaders();
        for (HttpHeaders headers : headerses) {
            result.addAll(headers);
        }
        return result;
    }

}
