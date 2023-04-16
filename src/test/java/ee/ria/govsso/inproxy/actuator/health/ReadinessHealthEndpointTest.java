package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.BaseTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class ReadinessHealthEndpointTest extends BaseTest {

    @Test
    void healthReadiness_WhenAllIncludedServicesUp_RespondsWith200() {
        given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }
}
