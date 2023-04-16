package ee.ria.govsso.inproxy;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(webEnvironment = RANDOM_PORT)
public abstract class BaseTest extends BaseTestLoggingAssertion {

    protected static final WireMockServer HYDRA_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(14442)
            .keystorePath("src/test/resources/hydra.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );
    protected static final WireMockServer SESSION_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(15442)
            .keystorePath("src/test/resources/session.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );
    protected static final WireMockServer ADMIN_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(17442)
            .keystorePath("src/test/resources/admin.localhost.keystore.p12")
            .keystorePassword("changeit")
            .keyManagerPassword("changeit")
            .notifier(new ConsoleNotifier(true))
    );

    @LocalServerPort
    protected int port;

    @BeforeAll
    static void setUpAll() {
        configureRestAssured();
        HYDRA_MOCK_SERVER.start();
        SESSION_MOCK_SERVER.start();
        ADMIN_MOCK_SERVER.start();
    }

    private static void configureRestAssured() {
        RestAssured.filters(new ResponseLoggingFilter());
        RestAssured.config = RestAssured.config().redirect(redirectConfig().followRedirects(false));
    }

    @BeforeEach
    public void beforeEachTest() {
        RestAssured.port = port;
        HYDRA_MOCK_SERVER.resetAll();
        SESSION_MOCK_SERVER.resetAll();
        ADMIN_MOCK_SERVER.resetAll();
    }
}
