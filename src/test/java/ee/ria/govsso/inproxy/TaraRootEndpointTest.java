package ee.ria.govsso.inproxy;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.blankOrNullString;
import static org.hamcrest.Matchers.equalTo;
@ActiveProfiles({"tara"})
public class TaraRootEndpointTest extends BaseTest {

    @Test
    void rootPath_RedirectsWith302() {
        given()
                .when()
                .get("/")
                .then()
                .assertThat()
                .statusCode(302)
                .header("Location", equalTo("https://www.ria.ee/riigi-infosusteem/elektrooniline-identiteet-ja-usaldusteenused/kesksed-autentimisteenused#tara"))
                .body(blankOrNullString());
    }
}
