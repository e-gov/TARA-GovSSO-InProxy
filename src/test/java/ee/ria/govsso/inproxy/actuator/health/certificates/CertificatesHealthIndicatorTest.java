package ee.ria.govsso.inproxy.actuator.health.certificates;

import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;

import java.util.ArrayList;
import java.util.List;

import static ee.ria.govsso.inproxy.actuator.health.certificates.CertificateInfoTestUtil.activeCertInfoBuilder;
import static ee.ria.govsso.inproxy.actuator.health.certificates.CertificateInfoTestUtil.expiredCertInfoBuilder;
import static ee.ria.govsso.inproxy.actuator.health.certificates.CertificateInfoTestUtil.inactiveCertInfoBuilder;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CertificatesHealthIndicatorTest {

    @Test
    void health_allActiveCertificates_statusUP() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(activeCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        CertificatesHealthIndicator healthIndicator = new CertificatesHealthIndicator(certificateInfoCache);

        assertEquals(Status.UP, healthIndicator.health().getStatus());
    }

    @Test
    void health_noActiveCertificates_statusDOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(expiredCertInfoBuilder().build());
        certificateInfos.add(inactiveCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        CertificatesHealthIndicator healthIndicator = new CertificatesHealthIndicator(certificateInfoCache);

        assertEquals(Status.DOWN, healthIndicator.health().getStatus());
    }

    @Test
    void health_activeAndExpiredCertificates_statusUNKOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(expiredCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        CertificatesHealthIndicator healthIndicator = new CertificatesHealthIndicator(certificateInfoCache);

        assertEquals(Status.UNKNOWN, healthIndicator.health().getStatus());
    }

    @Test
    void health_activeAndInactiveCertificates_statusUNKOWN() {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        certificateInfos.add(activeCertInfoBuilder().build());
        certificateInfos.add(inactiveCertInfoBuilder().build());

        CertificateInfoCache certificateInfoCache = new CertificateInfoCache(certificateInfos);
        CertificatesHealthIndicator healthIndicator = new CertificatesHealthIndicator(certificateInfoCache);

        assertEquals(Status.UNKNOWN, healthIndicator.health().getStatus());
    }
}
