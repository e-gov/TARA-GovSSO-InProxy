package ee.ria.govsso.inproxy.filter;

import static ee.ria.govsso.inproxy.filter.IpAddressGatewayFilterFactory.CLIENT_ID_ATTR;

import ee.ria.govsso.inproxy.logging.CountingServerHttpResponseDecorator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.AbstractServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.ZonedDateTime;
import reactor.netty.http.server.HttpServerRequest;

@Component
@Order
public class CustomAccessLogFilter implements WebFilter {

  private static final Logger logger = LoggerFactory.getLogger(CustomAccessLogFilter.class);

  @Value("${tara-govsso-inproxy.enable-access-log}")
  private boolean enableAccessLog;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    if (!enableAccessLog) {
      return chain.filter(exchange);
    }

    long startTimeMillis = System.currentTimeMillis();
    ZonedDateTime requestTime = ZonedDateTime.now();

    CountingServerHttpResponseDecorator decoratedResponse =
        new CountingServerHttpResponseDecorator(exchange.getResponse());
    ServerWebExchange mutatedExchange = exchange.mutate()
        .response(decoratedResponse)
        .build();

    return chain.filter(mutatedExchange)
        .doFinally(signalType -> {
          long duration = System.currentTimeMillis() - startTimeMillis;

          String clientId = mutatedExchange.getAttribute(CLIENT_ID_ATTR);
          clientId = (clientId == null) ? "-" : clientId;

          String remoteAddr = (mutatedExchange.getRequest().getRemoteAddress() != null)
              ? mutatedExchange.getRequest().getRemoteAddress().toString() : "-";
          String method = mutatedExchange.getRequest().getMethod().name();
          String uri = mutatedExchange.getRequest().getPath().toString();

          String protocol = "unknown";
          if (mutatedExchange.getRequest() instanceof AbstractServerHttpRequest abstractserverhttprequest) {
            HttpServerRequest nativeRequest = (abstractserverhttprequest).getNativeRequest();
            protocol = nativeRequest.version().text();
          }

          HttpStatusCode statusCode = mutatedExchange.getResponse().getStatusCode();
          String status = (statusCode != null) ? String.valueOf(statusCode.value()) : "-";

          long realContentLength = decoratedResponse.getByteCount();
          String contentLengthStr = (realContentLength > 0) ? String.valueOf(realContentLength) : "-";

          String logMessage = String.format("%s - %s [%s] \"%s %s %s\" %s %s %d",
              remoteAddr,
              clientId,
              requestTime,
              method,
              uri,
              protocol,
              status,
              contentLengthStr,
              duration);

          logger.info(logMessage);
        });
  }
}
