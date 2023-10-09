package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import io.restassured.response.ValidatableResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@ActiveProfiles({"govsso"})
class ApplicationHealthEndpointTest extends HealthEndpointTest {

    public ApplicationHealthEndpointTest(
            @Autowired TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService) {
        super(tokenRequestAllowedIpAddressesService);
    }

    @Test
    void health_WhenAllComponentsUp_RespondsWith200() {
        mockAdminHealthIndicatorUp();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("components.keySet()", equalTo(
                        Set.of("admin", "certificates", "diskSpace", "livenessState", "ping", "readinessState",
                                "refreshScope")))
                .body("components.admin.status", equalTo("UP"))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.livenessState.status", equalTo("UP"))
                .body("components.ping.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("components.refreshScope.status", equalTo("UP"))
                .body("groups", equalTo(List.of("liveness", "readiness")));

        assertCertificatesHealthUp(response, "components.certificates.");
    }

    // "/actuator/health/readiness" endpoint outcome depends on other services (including GovSSO Session status),
    // but readiness in general health endpoint does not.
    @Test
    void health_WhenAllComponentsButAdminUp_RespondsWith503ButReadinessUp() {
        mockAdminHealthIndicatorDown();

        ValidatableResponse response = given()
                .when()
                .get("/actuator/health")
                .then()
                .assertThat()
                .statusCode(503)
                .body("status", equalTo("DOWN"))
                .body("components.keySet()", equalTo(
                        Set.of("admin", "certificates", "diskSpace", "livenessState", "ping", "readinessState",
                                "refreshScope")))
                .body("components.admin.status", equalTo("DOWN"))
                .body("components.diskSpace.status", equalTo("UP"))
                .body("components.livenessState.status", equalTo("UP"))
                .body("components.ping.status", equalTo("UP"))
                .body("components.readinessState.status", equalTo("UP"))
                .body("components.refreshScope.status", equalTo("UP"))
                .body("groups", equalTo(List.of("liveness", "readiness")));

        assertCertificatesHealthUp(response, "components.certificates.");
        assertErrorIsLogged("Unable to update the list of allowed IP-address ranges: 400 Bad Request from GET https://admin.localhost:17442/clients/tokenrequestallowedipaddresses");
    }
}
