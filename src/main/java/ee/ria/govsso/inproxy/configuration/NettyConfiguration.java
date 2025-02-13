package ee.ria.govsso.inproxy.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.netty.NettyReactiveWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.stereotype.Component;
import reactor.netty.http.server.logging.AccessLog;

@Component
public class NettyConfiguration implements WebServerFactoryCustomizer<NettyReactiveWebServerFactory> {

    @Value("${tara-govsso-inproxy.enable-access-log}")
    private boolean enableAccessLog;

    @Override
    public void customize(NettyReactiveWebServerFactory factory) {
        // Based on reactor.netty.http.server.logging.BaseAccessLogHandler
        factory.addServerCustomizers(httpServer -> httpServer.accessLog(enableAccessLog,
            args -> {
                CharSequence clientIdSequence = args.requestHeader("X-ClientId");
                String clientId = (clientIdSequence != null) ? clientIdSequence.toString() : "-";
                return AccessLog.create("{} - {} [{}] \"{} {} {}\" {} {} {}",
                    args.remoteAddress(),
                    clientId,
                    args.zonedDateTime(),
                    args.method(),
                    args.uri(),
                    args.protocol(),
                    args.status(),
                    args.contentLength() > -1L ? args.contentLength() : "-",
                    args.duration());
            }
        ));
    }
}
