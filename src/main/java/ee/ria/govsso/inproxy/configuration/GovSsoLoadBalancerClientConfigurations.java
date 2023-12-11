package ee.ria.govsso.inproxy.configuration;

import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClient;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClients;
import org.springframework.context.annotation.Profile;

@Profile("govsso")
@LoadBalancerClients(value = {
        @LoadBalancerClient(value = "hydra", configuration = LoadBalancingConfiguration.class),
        @LoadBalancerClient(value = "session", configuration = LoadBalancingConfiguration.class)
})
public class GovSsoLoadBalancerClientConfigurations {
}
