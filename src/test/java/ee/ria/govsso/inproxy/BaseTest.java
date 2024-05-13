package ee.ria.govsso.inproxy;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import io.restassured.RestAssured;
import io.restassured.filter.log.ResponseLoggingFilter;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.io.File;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.config.RedirectConfig.redirectConfig;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Slf4j
@SpringBootTest(
        webEnvironment = RANDOM_PORT,
        classes = { Application.class, MockPropertyBeanConfiguration.class})
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
    protected static final WireMockServer TARA_MOCK_SERVER = new WireMockServer(WireMockConfiguration.wireMockConfig()
            .httpDisabled(true)
            .httpsPort(16442)
            .keystorePath("src/test/resources/tara.localhost.keystore.p12")
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
        createStubsForScheduledTasks();
        HYDRA_MOCK_SERVER.start();
        SESSION_MOCK_SERVER.start();
        TARA_MOCK_SERVER.start();
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
        TARA_MOCK_SERVER.resetAll();
        ADMIN_MOCK_SERVER.resetAll();
        createStubsForScheduledTasks();
    }

    private static void createStubsForScheduledTasks() {
        SESSION_MOCK_SERVER.stubFor(get(urlEqualTo("/actuator/health/readiness"))
                .willReturn(aResponse()
                        .withStatus(200)));
        HYDRA_MOCK_SERVER.stubFor(get(urlEqualTo("/health/ready"))
                .willReturn(aResponse()
                        .withStatus(200)));
        ADMIN_MOCK_SERVER.stubFor(get(urlPathEqualTo("/clients/tokenrequestallowedipaddresses"))
                .willReturn(aResponse()
                        .withStatus(200)));
        TARA_MOCK_SERVER.stubFor(get(urlPathEqualTo("/actuator/health/readiness"))
                .willReturn(aResponse()
                        .withStatus(200)));
    }

    @AfterAll
    public static void cleanUp() {
        new File("target/ipaddresses").delete();
    }
}
