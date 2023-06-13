package ee.ria.govsso.inproxy.actuator.health;

import ee.ria.govsso.inproxy.service.TokenRequestAllowedIpAddressesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminHealthIndicator implements HealthIndicator {

    private final TokenRequestAllowedIpAddressesService tokenRequestAllowedIpAddressesService;

    @Override
    public Health health() {
        return tokenRequestAllowedIpAddressesService.isLastRequestToAdminSuccessful()
                ? Health.up().build()
                : Health.down().build();
    }
}
