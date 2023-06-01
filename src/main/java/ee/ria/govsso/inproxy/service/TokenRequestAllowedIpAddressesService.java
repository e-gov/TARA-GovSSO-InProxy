package ee.ria.govsso.inproxy.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.configuration.properties.AdminConfigurationProperties;
import ee.ria.govsso.inproxy.logging.ClientRequestLogger;
import ee.ria.govsso.inproxy.util.ExceptionUtil;
import inet.ipaddr.IPAddressString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
public class TokenRequestAllowedIpAddressesService {

    private final ClientRequestLogger adminRequestLogger;
    private final AdminConfigurationProperties adminConfigurationProperties;
    private final ObjectMapper objectMapper;
    private final WebClient webclient;
    private final File file;

    public static final String IP_ADDRESSES_URL = "/clients/tokenrequestallowedipaddresses";
    private static final ParameterizedTypeReference<Map<String, List<String>>> PARAMETERIZED_TYPE_REFERENCE = new ParameterizedTypeReference<>() {
    };

    public Map<String, List<String>> tokenRequestAllowedIpAddresses = Map.of();

    public TokenRequestAllowedIpAddressesService(ClientRequestLogger adminRequestLogger,
                                                 AdminConfigurationProperties adminConfigurationProperties,
                                                 ObjectMapper objectMapper,
                                                 WebClient webclient) {
        this.adminRequestLogger = adminRequestLogger;
        this.adminConfigurationProperties = adminConfigurationProperties;
        this.objectMapper = objectMapper;
        this.webclient = webclient;
        file = new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath());

        log.info("Loading the list of allowed IP-address ranges from file '{}'", file.getAbsolutePath());
        loadIpAddressesFromFileIgnoringExceptions();
        log.info("Saving the list of allowed IP-address ranges to file '{}' to check writability", file.getAbsolutePath());
        saveIpAddressesToFile();
    }

    @Scheduled(fixedRateString = "${govsso-inproxy.admin.token-request-allowed-ip-addresses-refresh-interval-in-milliseconds:60000}")
    public void updateAllowedIpsTask() {
        try {
            queryIpAddressesFromAdminService();
            saveIpAddressesToFile();
        } catch (Exception ex) {
            log.error("Unable to update the list of allowed IP-address ranges: {}",
                    ExceptionUtil.getCauseMessages(ex),
                    ex);
        }
    }

    public boolean isTokenRequestAllowed(String clientId, String sourceAddress) {
        IPAddressString requestIpAddress = new IPAddressString(sourceAddress);
        List<String> allowedClientIps = tokenRequestAllowedIpAddresses.get(clientId);

        if (allowedClientIps == null) {
            return false;
        }

        for (String allowedClientIp : allowedClientIps) {
            //TODO determine potential for optimization
            if (new IPAddressString(allowedClientIp).contains(requestIpAddress)) {
                return true;
            }
        }
        return false;
    }

    public void loadIpAddressesFromFileIgnoringExceptions() {
        try {
            tokenRequestAllowedIpAddresses = objectMapper.readValue(file, new TypeReference<>() {
            });
        } catch (Exception ex) {
            log.info("Unable to load the list of allowed IP-address ranges from file '{}': {}",
                    file.getAbsolutePath(),
                    ExceptionUtil.getCauseMessages(ex));
        }
    }

    private void queryIpAddressesFromAdminService() {
        String uri = adminConfigurationProperties.baseUrl() + IP_ADDRESSES_URL;
        adminRequestLogger.logRequest(uri, HttpMethod.GET);
        tokenRequestAllowedIpAddresses = webclient.get()
                .uri(uri)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .bodyToMono(PARAMETERIZED_TYPE_REFERENCE)
                .defaultIfEmpty(Map.of())
                .block();
        adminRequestLogger.logResponse(HttpStatus.OK.value(), tokenRequestAllowedIpAddresses);
    }

    private void saveIpAddressesToFile() {
        try {
            objectMapper.writeValue(file, tokenRequestAllowedIpAddresses);
        } catch (Exception ex) {
            throw new RuntimeException("Unable to save the list of allowed IP-address ranges to file '%s'"
                    .formatted(file.getAbsolutePath()),
                    ex);
        }
    }

}
