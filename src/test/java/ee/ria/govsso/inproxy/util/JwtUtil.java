package ee.ria.govsso.inproxy.util;

import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.SneakyThrows;
import lombok.experimental.UtilityClass;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@UtilityClass
public class JwtUtil {

    @SneakyThrows
    public static RSAKey generateTestRsaKeyPair() {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now()))
                .generate();
    }

}
