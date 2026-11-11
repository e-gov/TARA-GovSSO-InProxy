package ee.ria.govsso.inproxy.util.forwarded;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Slf4j
@RequiredArgsConstructor
public class XForwardedForForwardedChainResolver implements ForwardedChainResolver {

    public static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final TrustStrategy trustStrategy;

    @Override
    public List<String> resolve(ServerHttpRequest request) {
        if (!trustStrategy.shouldTrust(request)) {
            log.debug("Not trusting {} header value of request", X_FORWARDED_FOR);
            return List.of();
        }
        List<String> headerValues = request.getHeaders().getOrEmpty(X_FORWARDED_FOR);
        if (headerValues.isEmpty()) {
            return List.of();
        }
        if (headerValues.size() > 1) {
            log.debug("Multiple {} headers present, ignoring all", X_FORWARDED_FOR);
            return List.of();
        }
        String headerValue = headerValues.get(0);
        return Arrays.stream(StringUtils.split(headerValue, ','))
                .map(StringUtils::trimToNull)
                .filter(Objects::nonNull)
                .toList();
    }

    @FunctionalInterface
    public interface TrustStrategy {

        boolean shouldTrust(ServerHttpRequest request);

        static TrustStrategy always() {
            return request -> true;
        }

        static TrustStrategy never() {
            return request -> false;
        }

    }
}
