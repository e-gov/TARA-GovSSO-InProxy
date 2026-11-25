package ee.ria.govsso.inproxy.filter;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.fail;

public class MockFilterChain implements WebFilterChain {

    private ServerWebExchange exchange;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange) {
        if(exchange == null) {
            fail("WebFilterChain.filter(...)` does not accept `null`");
        }
        if (this.exchange != null) {
            fail("`WebFilterChain.filter(...)` must only be called once.");
        }
        this.exchange = exchange;
        return Mono.empty();
    }

    public ServerWebExchange getCapturedExchange() {
        if (this.exchange == null) {
            fail("`WebFilterChain.filter(...)` was never called.");
        }
        return exchange;
    }

}
