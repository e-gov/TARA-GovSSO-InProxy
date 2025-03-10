package ee.ria.govsso.inproxy.actuator.health.certificates;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.CompositeHealthContributor;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.ResourceUtils;

import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

@Configuration
@RequiredArgsConstructor
public class CertificatesHealthConfiguration {

    @Bean
    @SneakyThrows
    public KeyStore serverKeyStore(ServerProperties serverProperties) {
        Ssl sslProperties = serverProperties.getSsl();
        if (sslProperties == null) {
            return null;
        }
        KeyStore keyStore = KeyStore.getInstance(sslProperties.getKeyStoreType());
        char[] password = sslProperties.getKeyStorePassword().toCharArray();
        URL url = ResourceUtils.getURL(sslProperties.getKeyStore());
        try (InputStream trustStoreFile = url.openStream()) {
            keyStore.load(trustStoreFile, password);
        }
        return keyStore;
    }

    @Bean
    public CompositeHealthContributor certificatesHealthContributor(
        KeyStore adminTrustStore,
        HttpClientProperties gatewayHttpClientProperties,
        @Autowired(required = false) KeyStore serverKeyStore) {
        Map<String, HealthIndicator> map = new HashMap<>();

        map.put("adminTrustStore", certificatesHealthIndicator(adminTrustStore));
        map.put("gatewayTrustStore", new CertificatesHealthIndicator(
            new CertificateInfoCache(CertificateInfoLoader.loadCertificateInfos(gatewayHttpClientProperties))
        ));
        if (serverKeyStore != null) {
            map.put("serverKeyStore", certificatesHealthIndicator(serverKeyStore));
        }
        return CompositeHealthContributor.fromMap(map);
    }

    private static CertificatesHealthIndicator certificatesHealthIndicator(KeyStore trustStore) {
        return new CertificatesHealthIndicator(
                new CertificateInfoCache(CertificateInfoLoader.loadCertificateInfos(trustStore))
        );
    }

}
