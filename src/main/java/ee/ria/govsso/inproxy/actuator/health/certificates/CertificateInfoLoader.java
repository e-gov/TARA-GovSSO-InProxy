package ee.ria.govsso.inproxy.actuator.health.certificates;

import lombok.SneakyThrows;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.util.ResourceUtils;

import javax.naming.ldap.LdapName;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;

class CertificateInfoLoader {

    private static final String CERTIFICATE_TYPE_X_509 = "X.509";

    @SneakyThrows
    static List<CertificateInfo> loadCertificateInfos(KeyStore trustStore) {
        List<CertificateInfo> certificateInfos = new ArrayList<>();
        Enumeration<String> aliases = trustStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate certificate = trustStore.getCertificate(alias);
            if (certificate != null && CERTIFICATE_TYPE_X_509.equals(certificate.getType())) {
                certificateInfos.add(buildCertificateInfo(alias, (X509Certificate) certificate));
            }
        }

        certificateInfos.sort(Comparator.comparing(CertificateInfo::getAlias));
        return certificateInfos;
    }

    @SneakyThrows
    static List<CertificateInfo> loadCertificateInfos(HttpClientProperties httpClientProperties) {
        // Loading is same as in org.springframework.cloud.gateway.config.AbstractSslConfigurer.getTrustedX509CertificatesForTrustManager
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> allCerts = new ArrayList<>();
        for (String path : httpClientProperties.getSsl().getTrustedX509Certificates()) {
            URL url = ResourceUtils.getURL(path);
            try (InputStream inStream = url.openStream()) {
                Collection<? extends Certificate> certs = certificateFactory.generateCertificates(inStream);
                allCerts.addAll((Collection<? extends X509Certificate>) certs);
            }
        }

        return allCerts.stream()
                .map(certificate -> buildCertificateInfo(getCn(certificate), certificate))
                .sorted(Comparator.comparing(CertificateInfo::getAlias))
                .toList();
    }

    @SneakyThrows
    private static String getCn(X509Certificate certificate) {
        String subjectName = certificate.getSubjectX500Principal().getName();
        return new LdapName(subjectName).getRdns().stream()
                .filter(rdn -> rdn.getType().equalsIgnoreCase("cn"))
                .map(rdn -> rdn.getValue().toString()).findFirst().get();
    }

    private static CertificateInfo buildCertificateInfo(String alias, X509Certificate certificate) {
        return CertificateInfo.builder()
                .alias(alias)
                .validFrom(certificate.getNotBefore().toInstant())
                .validTo(certificate.getNotAfter().toInstant())
                .subjectDN(certificate.getSubjectX500Principal().getName())
                .serialNumber(certificate.getSerialNumber().toString())
                .build();
    }
}
