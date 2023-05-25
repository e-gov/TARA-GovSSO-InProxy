package ee.ria.govsso.inproxy.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.ria.govsso.inproxy.configuration.properties.AdminConfigurationProperties;
import ee.ria.govsso.inproxy.util.ExceptionUtil;
import inet.ipaddr.IPAddressString;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenRequestAllowedIpAddressesService {
    private final AdminConfigurationProperties adminConfigurationProperties;
    private final ObjectMapper objectMapper;
    private final ConfigurableApplicationContext ctx;

    public static final String IP_ADDRESSES_URL = "/clients/tokenrequestallowedipaddresses";
    private static final ParameterizedTypeReference<Map<String, List<String>>> PARAMETERIZED_TYPE_REFERENCE = new ParameterizedTypeReference<>(){};

    public Map<String, List<String>> tokenRequestAllowedIpAddresses = Map.of();

    private final WebClient webclient;

    @Scheduled(fixedRateString = "${govsso-inproxy.admin.token-request-allowed-ip-addresses-refresh-interval-in-milliseconds:60000}")
    public void updateAllowedIpsTask() {

        String uri = adminConfigurationProperties.baseUrl() + IP_ADDRESSES_URL;

        try {
            tokenRequestAllowedIpAddresses = webclient.get()
                    .uri(uri)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .bodyToMono(PARAMETERIZED_TYPE_REFERENCE)
                    .defaultIfEmpty(Map.of())
                    .block();
            try {
                saveIpAddressesToFile();
            } catch (Exception ex) {
                log.error("Unable to save the list of allowed IP-address ranges to file: {}", ExceptionUtil.getCauseMessages(ex), ex);
            }
        } catch (Exception ex) {
            log.error("Unable to update the list of allowed IP-address ranges: {}", ExceptionUtil.getCauseMessages(ex), ex);
        }
    }

    @PostConstruct
    public void initializeTokenRequestAllowedIpAddressesFromFile() {
        File file = new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath());
        try {
            tokenRequestAllowedIpAddresses = objectMapper.readValue(file, new TypeReference<>(){});
            if (!file.canWrite()) {
                log.error("Unable to write to file containing tokenRequestAllowedIpAddresses at path: " + file.getAbsolutePath());
                ctx.close();
            }
        } catch (FileNotFoundException ex) {
            log.info("File containing tokenRequestAllowedIpAddresses was not found: " + adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath());
        } catch (Exception ex) {
            log.error("Unable to read file containing tokenRequestAllowedIpAddresses: {}", ExceptionUtil.getCauseMessages(ex), ex);
        }
    }

    private void saveIpAddressesToFile() throws IOException {
        objectMapper.writeValue(new File(adminConfigurationProperties.tokenRequestAllowedIpAddressesStoragePath()), tokenRequestAllowedIpAddresses);
    }

    public boolean isTokenRequestAllowed(String clientId, String sourceAddress) {
        IPAddressString requestIpAddress = new IPAddressString(sourceAddress);
        List<String> allowedClientIps = tokenRequestAllowedIpAddresses.get(clientId);

        if (allowedClientIps == null) {
            return false;
        }

        for (String allowedClientIp: allowedClientIps) {
            //TODO determine potential for optimization
            if (new IPAddressString(allowedClientIp).contains(requestIpAddress)) {
                return true;
            }
        }
        return false;
    }
}