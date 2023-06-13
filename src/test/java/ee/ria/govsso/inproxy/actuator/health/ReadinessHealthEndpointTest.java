package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

class ReadinessHealthEndpointTest extends HealthEndpointTest {

    public ReadinessHealthEndpointTest(
            @Autowired TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService) {
        super(tokenRequestAllowedIpAddressesService);
    }

    @Test
    void healthReadiness_WhenAllIncludedComponentsUp_RespondsWith200() {
        mockAdminHealthIndicatorUp();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health/readiness")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.keySet()", equalTo(Set.of("certificates", "diskSpace", "readinessState", "refreshScope")))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("components.refreshScope.status", equalTo("UP"));

        assertCertificatesHealthUp(response, "components.certificates.");
    }
}
