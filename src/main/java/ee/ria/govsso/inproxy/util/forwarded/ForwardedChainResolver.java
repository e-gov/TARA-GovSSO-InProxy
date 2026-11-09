package ee.ria.govsso.inproxy.util.forwarded;

import org.springframework.http.server.reactive.ServerHttpRequest;

import java.util.List;

public interface ForwardedChainResolver {

    List<String> resolve(ServerHttpRequest request);

}
