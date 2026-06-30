package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.configuration.TestSchedulingConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.test.context.ActiveProfiles;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@ActiveProfiles("govsso")
// Do not extend BaseTest here: it replaces the real LoadBalancingConfiguration and would hide this startup path.
@SpringBootTest(
        webEnvironment = RANDOM_PORT,
        classes = {
                Application.class,
                MockPropertyBeanConfiguration.class,
                TestSchedulingConfiguration.class
        })
class LoadBalancingConfigurationStartupTest {

    @LocalServerPort
    private int port;

    @Autowired
    private LoadBalancerClientFactory loadBalancerClientFactory;

    @Test
    void inProxyHealthEndpointRespondsWithRealLoadBalancingHealthChecks() {
        given()
                .port(port)
                .when()
                .get("/actuator/health/liveness")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));

        assertThat(loadBalancerClientFactory.getInstance("hydra", ServiceInstanceListSupplier.class)).isNotNull();
    }

}
