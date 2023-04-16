package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.BaseTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class ApplicationHealthEndpointTest extends BaseTest {

    @Test
    void health_WhenAllServicesUp_RespondsWith200() {
        given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.livenessState.status", equalTo("UP"))
                .body("components.ping.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("groups", equalTo(List.of("liveness", "readiness")));
    }
}
