package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalToCompressingWhiteSpace;

@ActiveProfiles({"govsso"})
public class GovSsoHydraLogoutEndpointTest extends BaseTest {

    private static final String TRACE_PARENT_PARAMETER_NAME = "traceparent";
    private static final String TRACE_PARENT_PARAMETER_SAMPLE_VALUE = "00f067aa0ba902b7";

    @BeforeEach
    void setupServerMocks() {
        HYDRA_MOCK_SERVER.stubFor(any(urlPathEqualTo("/oauth2/sessions/logout"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json; charset=UTF-8")
                        .withBodyFile("mock_responses/hydra_oauth2_sessions_logout.json")));
    }

    @Test
    void hydra_oAuth2SessionsLogoutPostRequestQueryParamIdTokenHintContainingRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0Mjc1YzQwLWJmNzItNDU3MS1hNTIyLWY0Y2Q4ZDRhOGQ3YyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6InZkOUhVN3BISlBCMl90WUUxWkdZeXciLCJhdWQiOlsiY2xpZW50LWQiXSwiYXV0aF90aW1lIjoxNzMzNDUzOTgzLCJiaXJ0aGRhdGUiOiIxOTAzLTAzLTAzIiwiZXhwIjoxNzMzNDU0ODg0LCJmYW1pbHlfbmFtZSI6IlRFU1ROVU1CRVIiLCJnaXZlbl9uYW1lIjoiT0siLCJpYXQiOjE3MzM0NTM5ODQsImlzcyI6Imh0dHBzOi8vZ292c3NvLmRldi5yaWFpbnQuZWUvIiwianRpIjoiY2M4NzkwY2UtOWQzMS00ZWVkLTgyZDItZTk2YzQ3OWRmZTQ1Iiwibm9uY2UiOiJfSXFmWTVGNTFnY1l2bHNETnJzbjd2eDlCZXpZQ2RMcDR2WmlTTVo2VjNVIiwicmF0IjoxNzMzNDUzOTY0LCJyZXByZXNlbnRlZV9saXN0Ijp7Imxpc3QiOlt7Im5hbWUiOiJvc2HDvGhpbmcgXCJLYWRyaWtlbmVcIiIsInN1YiI6IkVFMTAwNTA1NDIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT8OcIEFzc290cmFucyIsInN1YiI6IkVFMTAwNTk4NjIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiQUtUU0lBU0VMVFMgVEFMTElOTkEgU0FEQU0iLCJzdWIiOiJFRTEwMTM3MzE5IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9zYcO8aGluZyBLSU5FWCBBUlZVVElTQUxPTkciLCJzdWIiOiJFRTEwMjMwMDM3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkFrdHNpYXNlbHRzIFRhbGxpbm5hIExpbm5hdHJhbnNwb3J0Iiwic3ViIjoiRUUxMDMxMjk2MCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJOb3J0YWwgQVMiLCJzdWIiOiJFRTEwMzkxMTMxIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlBBVU5WRVJFIEFHUk8gT8OcIiwic3ViIjoiRUUxMDUzNTg0OCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgTmV0IEdyb3VwIiwic3ViIjoiRUUxMDU4NTQzOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgS2FyamFtw7Vpc2EiLCJzdWIiOiJFRTEwNzYzOTU3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9TQcOcSElORyBJTkNIQ0FQRSBNT1RPUlMgRVNUT05JQSIsInN1YiI6IkVFMTEwNzA3MzYiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT1NBw5xISU5HIFBSSU5UMjQiLCJzdWIiOiJFRTExNDE1NTQzIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkNsYXJpZmllZCBTZWN1cml0eSBPw5wiLCJzdWIiOiJFRTEyMTY0NTQwIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRvZGEgR2xvYmFsIE_DnCIsInN1YiI6IkVFMTQyNjk2NTEiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiRElHQVRPIE_DnCIsInN1YiI6IkVFMTQyOTE1MzgiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiSklOIE_DnCIsInN1YiI6IkVFMTQ3MTQ4NDkiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiTXVpbnN1c2thaXRzZWFtZXQiLCJzdWIiOiJFRTcwMDAwOTU4IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRBUkJJSkFLQUlUU0UgSkEgVEVITklMSVNFIErDhFJFTEVWQUxWRSBBTUVUIiwic3ViIjoiRUU3MDAwMzIxOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJSSUlHSSBJTkZPU8OcU1RFRU1JIEFNRVQiLCJzdWIiOiJFRTcwMDA2MzE3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkVFU1RJIE5PT1JTT09Uw5bDllRBSkFURSBLT0dVIiwic3ViIjoiRUU4MDExOTY0MyIsInR5cGUiOiJMRUdBTF9QRVJTT04ifV0sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJmNTA2NmQ5OS0zZGE0LTQxYzUtOWMwMy0zNzU2NTczYjc3MjMiLCJzdWIiOiJFRTMwMzAzMDM5OTE0In0.ijobyiCR0R2gFiTpbLhZV-Yo14XDW2iIqA6KKBpdb1MqxqXfJNhLoFZbrD4-M1XIq3qIWnF2HiK3kZ5uhUpClR0_Xtzv718NJkF9jlncPE5w523uM-77Y9sWOdSUmQWEZeTTdgKlER-E4MPdcl7NGChJhyaNFhFxUoQ6mijSQDviFXpzwVWw-D2VHoLmFkdJRI7MshJLcpYpRbAIoZuSMq30CLMQi66ArE9zw0caQs6s9Ybgjhw_Y15hlDAL_lrL1YoxrjV5oFbb_7nXI77X5auRiyz7i_H7v0LnNj7RCqijE3EdKSJayYDkScc9aHGJbiYr_ckhAuliMaG5K09EwWrfrpY4DR8hBb8X4gvBijDHjvuyNGgUnH9T8_ay6oBrrDk3BJM6zAVgTBNgTpAjQDO6Zf5jM1LWhhbQ4SGsf5I0q7QLH7QbTQN8AEv2musQ7MQELKzHvih2qTX9xmXVL0ajAm9iAWkuWvotI8NWI7X5y5NwCdOe4jXIEiIxq4CzbiLRWfnsTnSaXYz0d9_5uaMEyfM5I6aMWHVouB2_mNDbjBt09HyW7fThOM3kHt0vnqeUU_ckg9aoepKnBdKn-egorjN-K1EGvtqFKoWwZlFP_q33kpxum0JdR_rJoYchUyRuDg_vpsqfNt5_mN7NIhWgksyYtSCA0ZAoFQ73p6k")
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=The+%27id_token_hint%27+query+parameter+is+not+allowed+when+using+logout+request+with+http+POST+method%2C+it+must+be+passed+as+a+form+parameter")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_oAuth2SessionsLogoutPostRequestFormParamIdTokenHintContainingRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .formParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0Mjc1YzQwLWJmNzItNDU3MS1hNTIyLWY0Y2Q4ZDRhOGQ3YyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6InZkOUhVN3BISlBCMl90WUUxWkdZeXciLCJhdWQiOlsiY2xpZW50LWQiXSwiYXV0aF90aW1lIjoxNzMzNDUzOTgzLCJiaXJ0aGRhdGUiOiIxOTAzLTAzLTAzIiwiZXhwIjoxNzMzNDU0ODg0LCJmYW1pbHlfbmFtZSI6IlRFU1ROVU1CRVIiLCJnaXZlbl9uYW1lIjoiT0siLCJpYXQiOjE3MzM0NTM5ODQsImlzcyI6Imh0dHBzOi8vZ292c3NvLmRldi5yaWFpbnQuZWUvIiwianRpIjoiY2M4NzkwY2UtOWQzMS00ZWVkLTgyZDItZTk2YzQ3OWRmZTQ1Iiwibm9uY2UiOiJfSXFmWTVGNTFnY1l2bHNETnJzbjd2eDlCZXpZQ2RMcDR2WmlTTVo2VjNVIiwicmF0IjoxNzMzNDUzOTY0LCJyZXByZXNlbnRlZV9saXN0Ijp7Imxpc3QiOlt7Im5hbWUiOiJvc2HDvGhpbmcgXCJLYWRyaWtlbmVcIiIsInN1YiI6IkVFMTAwNTA1NDIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT8OcIEFzc290cmFucyIsInN1YiI6IkVFMTAwNTk4NjIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiQUtUU0lBU0VMVFMgVEFMTElOTkEgU0FEQU0iLCJzdWIiOiJFRTEwMTM3MzE5IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9zYcO8aGluZyBLSU5FWCBBUlZVVElTQUxPTkciLCJzdWIiOiJFRTEwMjMwMDM3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkFrdHNpYXNlbHRzIFRhbGxpbm5hIExpbm5hdHJhbnNwb3J0Iiwic3ViIjoiRUUxMDMxMjk2MCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJOb3J0YWwgQVMiLCJzdWIiOiJFRTEwMzkxMTMxIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlBBVU5WRVJFIEFHUk8gT8OcIiwic3ViIjoiRUUxMDUzNTg0OCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgTmV0IEdyb3VwIiwic3ViIjoiRUUxMDU4NTQzOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgS2FyamFtw7Vpc2EiLCJzdWIiOiJFRTEwNzYzOTU3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9TQcOcSElORyBJTkNIQ0FQRSBNT1RPUlMgRVNUT05JQSIsInN1YiI6IkVFMTEwNzA3MzYiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT1NBw5xISU5HIFBSSU5UMjQiLCJzdWIiOiJFRTExNDE1NTQzIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkNsYXJpZmllZCBTZWN1cml0eSBPw5wiLCJzdWIiOiJFRTEyMTY0NTQwIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRvZGEgR2xvYmFsIE_DnCIsInN1YiI6IkVFMTQyNjk2NTEiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiRElHQVRPIE_DnCIsInN1YiI6IkVFMTQyOTE1MzgiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiSklOIE_DnCIsInN1YiI6IkVFMTQ3MTQ4NDkiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiTXVpbnN1c2thaXRzZWFtZXQiLCJzdWIiOiJFRTcwMDAwOTU4IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRBUkJJSkFLQUlUU0UgSkEgVEVITklMSVNFIErDhFJFTEVWQUxWRSBBTUVUIiwic3ViIjoiRUU3MDAwMzIxOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJSSUlHSSBJTkZPU8OcU1RFRU1JIEFNRVQiLCJzdWIiOiJFRTcwMDA2MzE3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkVFU1RJIE5PT1JTT09Uw5bDllRBSkFURSBLT0dVIiwic3ViIjoiRUU4MDExOTY0MyIsInR5cGUiOiJMRUdBTF9QRVJTT04ifV0sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJmNTA2NmQ5OS0zZGE0LTQxYzUtOWMwMy0zNzU2NTczYjc3MjMiLCJzdWIiOiJFRTMwMzAzMDM5OTE0In0.ijobyiCR0R2gFiTpbLhZV-Yo14XDW2iIqA6KKBpdb1MqxqXfJNhLoFZbrD4-M1XIq3qIWnF2HiK3kZ5uhUpClR0_Xtzv718NJkF9jlncPE5w523uM-77Y9sWOdSUmQWEZeTTdgKlER-E4MPdcl7NGChJhyaNFhFxUoQ6mijSQDviFXpzwVWw-D2VHoLmFkdJRI7MshJLcpYpRbAIoZuSMq30CLMQi66ArE9zw0caQs6s9Ybgjhw_Y15hlDAL_lrL1YoxrjV5oFbb_7nXI77X5auRiyz7i_H7v0LnNj7RCqijE3EdKSJayYDkScc9aHGJbiYr_ckhAuliMaG5K09EwWrfrpY4DR8hBb8X4gvBijDHjvuyNGgUnH9T8_ay6oBrrDk3BJM6zAVgTBNgTpAjQDO6Zf5jM1LWhhbQ4SGsf5I0q7QLH7QbTQN8AEv2musQ7MQELKzHvih2qTX9xmXVL0ajAm9iAWkuWvotI8NWI7X5y5NwCdOe4jXIEiIxq4CzbiLRWfnsTnSaXYz0d9_5uaMEyfM5I6aMWHVouB2_mNDbjBt09HyW7fThOM3kHt0vnqeUU_ckg9aoepKnBdKn-egorjN-K1EGvtqFKoWwZlFP_q33kpxum0JdR_rJoYchUyRuDg_vpsqfNt5_mN7NIhWgksyYtSCA0ZAoFQ73p6k")
                .when()
                .post("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(postRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithRepresenteeList_isRedirectedToErrorPage() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0Mjc1YzQwLWJmNzItNDU3MS1hNTIyLWY0Y2Q4ZDRhOGQ3YyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6InZkOUhVN3BISlBCMl90WUUxWkdZeXciLCJhdWQiOlsiY2xpZW50LWQiXSwiYXV0aF90aW1lIjoxNzMzNDUzOTgzLCJiaXJ0aGRhdGUiOiIxOTAzLTAzLTAzIiwiZXhwIjoxNzMzNDU0ODg0LCJmYW1pbHlfbmFtZSI6IlRFU1ROVU1CRVIiLCJnaXZlbl9uYW1lIjoiT0siLCJpYXQiOjE3MzM0NTM5ODQsImlzcyI6Imh0dHBzOi8vZ292c3NvLmRldi5yaWFpbnQuZWUvIiwianRpIjoiY2M4NzkwY2UtOWQzMS00ZWVkLTgyZDItZTk2YzQ3OWRmZTQ1Iiwibm9uY2UiOiJfSXFmWTVGNTFnY1l2bHNETnJzbjd2eDlCZXpZQ2RMcDR2WmlTTVo2VjNVIiwicmF0IjoxNzMzNDUzOTY0LCJyZXByZXNlbnRlZV9saXN0Ijp7Imxpc3QiOlt7Im5hbWUiOiJvc2HDvGhpbmcgXCJLYWRyaWtlbmVcIiIsInN1YiI6IkVFMTAwNTA1NDIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT8OcIEFzc290cmFucyIsInN1YiI6IkVFMTAwNTk4NjIiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiQUtUU0lBU0VMVFMgVEFMTElOTkEgU0FEQU0iLCJzdWIiOiJFRTEwMTM3MzE5IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9zYcO8aGluZyBLSU5FWCBBUlZVVElTQUxPTkciLCJzdWIiOiJFRTEwMjMwMDM3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkFrdHNpYXNlbHRzIFRhbGxpbm5hIExpbm5hdHJhbnNwb3J0Iiwic3ViIjoiRUUxMDMxMjk2MCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJOb3J0YWwgQVMiLCJzdWIiOiJFRTEwMzkxMTMxIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlBBVU5WRVJFIEFHUk8gT8OcIiwic3ViIjoiRUUxMDUzNTg0OCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgTmV0IEdyb3VwIiwic3ViIjoiRUUxMDU4NTQzOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJPc2HDvGhpbmcgS2FyamFtw7Vpc2EiLCJzdWIiOiJFRTEwNzYzOTU3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6Ik9TQcOcSElORyBJTkNIQ0FQRSBNT1RPUlMgRVNUT05JQSIsInN1YiI6IkVFMTEwNzA3MzYiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiT1NBw5xISU5HIFBSSU5UMjQiLCJzdWIiOiJFRTExNDE1NTQzIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkNsYXJpZmllZCBTZWN1cml0eSBPw5wiLCJzdWIiOiJFRTEyMTY0NTQwIiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRvZGEgR2xvYmFsIE_DnCIsInN1YiI6IkVFMTQyNjk2NTEiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiRElHQVRPIE_DnCIsInN1YiI6IkVFMTQyOTE1MzgiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiSklOIE_DnCIsInN1YiI6IkVFMTQ3MTQ4NDkiLCJ0eXBlIjoiTEVHQUxfUEVSU09OIn0seyJuYW1lIjoiTXVpbnN1c2thaXRzZWFtZXQiLCJzdWIiOiJFRTcwMDAwOTU4IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IlRBUkJJSkFLQUlUU0UgSkEgVEVITklMSVNFIErDhFJFTEVWQUxWRSBBTUVUIiwic3ViIjoiRUU3MDAwMzIxOCIsInR5cGUiOiJMRUdBTF9QRVJTT04ifSx7Im5hbWUiOiJSSUlHSSBJTkZPU8OcU1RFRU1JIEFNRVQiLCJzdWIiOiJFRTcwMDA2MzE3IiwidHlwZSI6IkxFR0FMX1BFUlNPTiJ9LHsibmFtZSI6IkVFU1RJIE5PT1JTT09Uw5bDllRBSkFURSBLT0dVIiwic3ViIjoiRUU4MDExOTY0MyIsInR5cGUiOiJMRUdBTF9QRVJTT04ifV0sInN0YXR1cyI6IlJFUFJFU0VOVEVFX0xJU1RfQ1VSUkVOVCJ9LCJzaWQiOiJmNTA2NmQ5OS0zZGE0LTQxYzUtOWMwMy0zNzU2NTczYjc3MjMiLCJzdWIiOiJFRTMwMzAzMDM5OTE0In0.ijobyiCR0R2gFiTpbLhZV-Yo14XDW2iIqA6KKBpdb1MqxqXfJNhLoFZbrD4-M1XIq3qIWnF2HiK3kZ5uhUpClR0_Xtzv718NJkF9jlncPE5w523uM-77Y9sWOdSUmQWEZeTTdgKlER-E4MPdcl7NGChJhyaNFhFxUoQ6mijSQDviFXpzwVWw-D2VHoLmFkdJRI7MshJLcpYpRbAIoZuSMq30CLMQi66ArE9zw0caQs6s9Ybgjhw_Y15hlDAL_lrL1YoxrjV5oFbb_7nXI77X5auRiyz7i_H7v0LnNj7RCqijE3EdKSJayYDkScc9aHGJbiYr_ckhAuliMaG5K09EwWrfrpY4DR8hBb8X4gvBijDHjvuyNGgUnH9T8_ay6oBrrDk3BJM6zAVgTBNgTpAjQDO6Zf5jM1LWhhbQ4SGsf5I0q7QLH7QbTQN8AEv2musQ7MQELKzHvih2qTX9xmXVL0ajAm9iAWkuWvotI8NWI7X5y5NwCdOe4jXIEiIxq4CzbiLRWfnsTnSaXYz0d9_5uaMEyfM5I6aMWHVouB2_mNDbjBt09HyW7fThOM3kHt0vnqeUU_ckg9aoepKnBdKn-egorjN-K1EGvtqFKoWwZlFP_q33kpxum0JdR_rJoYchUyRuDg_vpsqfNt5_mN7NIhWgksyYtSCA0ZAoFQ73p6k")
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(302)
                .header(HttpHeaders.LOCATION, "/error/oidc?error=invalid_request&error_description=Logout+request+must+use+POST+method+if+the+id+token+from+%27id_token_hint%27+parameter+contains+a+%27representee_list%27+claim")
                .header(HttpHeaders.CACHE_CONTROL, "private, no-cache, no-store, must-revalidate");
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithoutRepresenteeList_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0Mjc1YzQwLWJmNzItNDU3MS1hNTIyLWY0Y2Q4ZDRhOGQ3YyIsInR5cCI6IkpXVCJ9.eyJhY3IiOiJoaWdoIiwiYW1yIjpbInNtYXJ0aWQiXSwiYXRfaGFzaCI6IlQwVDQ2MXdyOUQ3cFV2a0J2UFZ2SHciLCJhdWQiOlsiY2xpZW50LWMiXSwiYXV0aF90aW1lIjoxNzMzNzI3Nzk1LCJiaXJ0aGRhdGUiOiIxOTAzLTAzLTAzIiwiZXhwIjoxNzMzNzI4Njk2LCJmYW1pbHlfbmFtZSI6IlRFU1ROVU1CRVIiLCJnaXZlbl9uYW1lIjoiT0siLCJpYXQiOjE3MzM3Mjc3OTYsImlzcyI6Imh0dHBzOi8vZ292c3NvLmRldi5yaWFpbnQuZWUvIiwianRpIjoiOGJjNmRmZmQtODg1Ny00ZDBmLWI0ZmYtMGYzMzBmMjdhNWM0Iiwibm9uY2UiOiI1RXh1cDFmYUpZMktpM2MxQU5EYUY1OG4zaEZsWjFmNTBTRHcwb0tFNGUwIiwicmF0IjoxNzMzNzI3NzgxLCJzaWQiOiJiYzQzMGNjNi02MjRmLTQ5N2UtYTUyNS1iMDhkMmZlMjcxNGYiLCJzdWIiOiJFRTMwMzAzMDM5OTE0In0.goRbPPqfZ-oZa6Su0vrTKzl_PbAwbxpPbRq-OneuyEDZ_RVxdeBarDGTvYx_uLF2BdXeSE_jhUHDyLJu0O0Vl2yfpARPg-E56EondsjWRuylMNnYG_n-XRKQXdnbcOOqzRkwN9W3rVSfdwRaFymR-c5WrBggzrimDey6tTZbJ6JQKGqQMZQQo-AteoF9L9NUa0Z6JPF1ws8_GkqVgT1lH7oDMNsOlSiUZMBWiZgUxPseT30jEE0TdoIaY0QN_itd--dfKMBf-AI_IxiDeyxJCYJ2OowmzedPDcmoq6ARXYGO5SvRxl7yTJQW_FVt_dFKEV5GkLfWKgQlD7m5ND_wb4xRRMzrectM_46IejHMRyJgk-Mm1lDW1PAMWSjqq1aMkjCd1NpKbKNXxEuo7OhnOnNiCjRixfh4N4JgLLL5vd1Ii1YYIEop9v6fU8cKJifhzvFl47_n2rimgmtdFXcGMrHA5QBsi5BBLqxscxwkSKYtQrNX3ROJGAUuv7O7jvRVsGYH1565bYLs5VVdtWXnCnm_11hw27b6KT3zcieXuvvHGdGvYfI-2tdUsZvmfABrGZW1rUugR_AmfJGtlFqa1cJ02R1O-0fBT_FMIkSoJ1ojw7HIcdy2LeuwYzGMzkV2RkUdjZvCBbbx20_X5aLini_ttYyCakgU-jax1tgBRjU")
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "abcdefg", "abcdefg.12345"})
    void hydra_oAuth2SessionsLogoutGetRequestWithInvalidIdTokenHint_isSuccessful(String idToken) {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .queryParam("id_token_hint", idToken)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
    }

    @Test
    void hydra_oAuth2SessionsLogoutGetRequestWithMissingIdTokenHint_isSuccessful() {
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200);
    }


    @Test
    void hydra_oAuth2SessionsLogoutWithTraceParentParameter_AddsHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_sessions_logout.json");
        given()
                .queryParam("tRaCePaReNt", TRACE_PARENT_PARAMETER_SAMPLE_VALUE)
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlPathEqualTo("/oauth2/sessions/logout"))
                .withHeader(TRACE_PARENT_PARAMETER_NAME, equalTo(TRACE_PARENT_PARAMETER_SAMPLE_VALUE)));
    }

    @Test
    void hydra_oAuth2SessionsLogoutWithoutTraceParentParameter_DoesNotAddHeader() {
        String expectedResponse = TestUtils.getResourceAsString("__files/mock_responses/hydra_oauth2_sessions_logout.json");
        given()
                .when()
                .get("/oauth2/sessions/logout")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToCompressingWhiteSpace(expectedResponse));

        HYDRA_MOCK_SERVER.verify(getRequestedFor(urlEqualTo("/oauth2/sessions/logout"))
                .withoutHeader(TRACE_PARENT_PARAMETER_NAME));
    }

}
