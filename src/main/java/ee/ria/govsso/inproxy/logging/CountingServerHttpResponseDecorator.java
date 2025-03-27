package ee.ria.govsso.inproxy.logging;

import java.util.concurrent.atomic.AtomicLong;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Flux;
import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;

public class CountingServerHttpResponseDecorator extends ServerHttpResponseDecorator {
  private final AtomicLong byteCount = new AtomicLong(0);

  public CountingServerHttpResponseDecorator(ServerHttpResponse delegate) {
    super(delegate);
  }

  @Override
  public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
    Flux<? extends DataBuffer> flux = Flux.from(body)
        .doOnNext(dataBuffer ->
          byteCount.addAndGet(dataBuffer.readableByteCount()
        ));
    return super.writeWith(flux);
  }

  public long getByteCount() {
    return byteCount.get();
  }
}
