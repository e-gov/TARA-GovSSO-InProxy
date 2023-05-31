package ee.ria.govsso.inproxy.configuration;

import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

public class LoadBalancingConfiguration {

    @Bean
    public ServiceInstanceListSupplier instanceSupplier(ConfigurableApplicationContext context,
                                                        WebClient.Builder loadBalancedWebClientBuilder,
                                                        HttpClient gatewayHttpClient) {
        //To make health checks work with the secure configuration defined for Spring Cloud Gateway then
        //we need to create a WebClient that includes the HttpClient instance used by Spring Cloud Gateway.
        WebClient webClient = loadBalancedWebClientBuilder
                .clientConnector(new ReactorClientHttpConnector(gatewayHttpClient))
                .build();

        return ServiceInstanceListSupplier.builder()
                .withDiscoveryClient()
                .withHealthChecks(webClient)
                .build(context);
    }
}
