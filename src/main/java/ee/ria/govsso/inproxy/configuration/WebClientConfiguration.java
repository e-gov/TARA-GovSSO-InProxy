package ee.ria.govsso.inproxy.configuration;

import ee.ria.govsso.inproxy.configuration.properties.AdminConfigurationProperties;
import ee.ria.govsso.inproxy.logging.ClientRequestLogger;
import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

import static ee.ria.govsso.inproxy.logging.ClientRequestLogger.Service.ADMIN;

@Configuration
@EnableScheduling
@RequiredArgsConstructor
@ConfigurationPropertiesScan
class WebClientConfiguration {

    @Bean
    ClientRequestLogger adminRequestLogger() {
        return new ClientRequestLogger(ADMIN, TokenRequestAllowedIpAddressesService.class);
    }

    @Bean
    public WebClient adminWebClient(ClientRequestLogger requestLogger, KeyStore adminTrustStore) {
        SslContext sslContext = initSslContext(adminTrustStore);

        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(responseFilter(requestLogger))
                .build();
    }

    @Bean
    @SneakyThrows
    KeyStore adminTrustStore(AdminConfigurationProperties.AdminTlsConfigurationProperties tlsProperties) {
        InputStream trustStoreFile = tlsProperties.trustStore().getInputStream();
        KeyStore trustStore = KeyStore.getInstance(tlsProperties.trustStoreType());
        trustStore.load(trustStoreFile, tlsProperties.trustStorePassword().toCharArray());
        return trustStore;
    }

    @SneakyThrows
    private SslContext initSslContext(KeyStore trustStore) {
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);
        return SslContextBuilder.forClient().trustManager(trustManagerFactory).build();
    }

    private ExchangeFilterFunction responseFilter(ClientRequestLogger requestLogger) {
        // TODO Catch connection errors.
        return ExchangeFilterFunction.ofResponseProcessor(clientResponse -> {
            if (clientResponse.statusCode().isError()) {
                return clientResponse.bodyToMono(String.class)
                        .defaultIfEmpty("")
                        .flatMap(responseBody -> {
                            try {
                                requestLogger.logResponse(clientResponse.statusCode().value(), responseBody);
                                return Mono.just(clientResponse);
                            } catch (Exception ex) {
                                return Mono.error(new IllegalStateException("Failed to log response", ex));
                            }
                        });
            } else {
                return Mono.just(clientResponse);
            }
        });
    }
}
