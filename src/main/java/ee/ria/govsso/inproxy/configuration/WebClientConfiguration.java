package ee.ria.govsso.inproxy.configuration;

import ee.ria.govsso.inproxy.configuration.properties.AdminConfigurationProperties;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

@Configuration
@EnableScheduling
@RequiredArgsConstructor
@ConfigurationPropertiesScan
class WebClientConfiguration {

    @Bean
    public WebClient adminWebClient(KeyStore adminTrustStore) {
        SslContext sslContext = initSslContext(adminTrustStore);

        HttpClient httpClient = HttpClient.create()
                .secure(sslProviderBuilder -> sslProviderBuilder.sslContext(sslContext));
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
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
}
