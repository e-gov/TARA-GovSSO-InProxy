package ee.ria.govsso.inproxy.actuator.health.certificates;

import ee.ria.govsso.inproxy.BaseTest;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.config.HttpClientProperties;

import java.security.KeyStore;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@RequiredArgsConstructor(onConstructor_ = @Autowired)
class CertificateInfoLoaderTest extends BaseTest {

    private final KeyStore adminTrustStore;
    private final HttpClientProperties httpClientProperties;
    // TODO Verifying serverKeyStore would require setting up TLS between REST Assured client and Spring Boot server.

    @Test
    void loadCertificateInfos_adminTrustStore() {
        List<CertificateInfo> certificateInfos = CertificateInfoLoader.loadCertificateInfos(adminTrustStore);
        assertEquals(1, certificateInfos.size());
        CertificateInfo certificateInfo = certificateInfos.get(0);
        assertEquals("govsso-ca.localhost", certificateInfo.getAlias());
        assertEquals("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE", certificateInfo.getSubjectDN());
        assertNull(certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }

    @Test
    void loadCertificateInfos_gatewayTrustStore() {
        List<CertificateInfo> certificateInfos = CertificateInfoLoader.loadCertificateInfos(httpClientProperties);
        assertEquals(1, certificateInfos.size());
        CertificateInfo certificateInfo = certificateInfos.get(0);
        assertEquals("govsso-ca.localhost", certificateInfo.getAlias());
        assertEquals("CN=govsso-ca.localhost,O=govsso-local,L=Tallinn,C=EE", certificateInfo.getSubjectDN());
        assertNull(certificateInfo.getState());
        assertNull(certificateInfo.getWarning());
    }
}
