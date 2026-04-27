package ee.ria.govsso.inproxy.configuration;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.ReactiveDiscoveryClient;
import org.springframework.cloud.client.loadbalancer.LoadBalancerClientsProperties;
import org.springframework.cloud.loadbalancer.annotation.LoadBalancerClientSpecification;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.cloud.loadbalancer.support.LoadBalancerClientFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@TestConfiguration
public class TestLoadBalancingConfiguration {

    @Bean
    public LoadBalancerClientFactory loadBalancerClientFactory(LoadBalancerClientsProperties properties,
                                                               ObjectProvider<List<LoadBalancerClientSpecification>> configurations) {
        LoadBalancerClientFactory clientFactory = new LoadBalancerClientFactory(properties);
        List<LoadBalancerClientSpecification> specifications = configurations.getIfAvailable(Collections::emptyList);
        clientFactory.setConfigurations(withoutHealthChecks(specifications));
        return clientFactory;
    }

    private static List<LoadBalancerClientSpecification> withoutHealthChecks(List<LoadBalancerClientSpecification> specifications) {
        return specifications.stream()
                .map(TestLoadBalancingConfiguration::withoutHealthChecks)
                .toList();
    }

    private static LoadBalancerClientSpecification withoutHealthChecks(LoadBalancerClientSpecification specification) {
        return new LoadBalancerClientSpecification(
                specification.getName(),
                Arrays.stream(specification.getConfiguration())
                        .map(configurationClass -> LoadBalancingConfiguration.class.equals(configurationClass) ?
                                NoHealthCheckLoadBalancerClientConfiguration.class :
                                configurationClass)
                        .toArray(Class<?>[]::new));
    }

    /* Based on `ee.ria.govsso.inproxy.configuration.LoadBalancingConfiguration` but without health checks */
    public static class NoHealthCheckLoadBalancerClientConfiguration {

        @Bean
        public ServiceInstanceListSupplier instanceSupplier(ConfigurableApplicationContext context,
                                                            ReactiveDiscoveryClient discoveryClient) {
            return new LazyReactiveDiscoveryClientServiceInstanceListSupplier(discoveryClient, context.getEnvironment());
        }

        private static final class LazyReactiveDiscoveryClientServiceInstanceListSupplier implements ServiceInstanceListSupplier {

            private final ReactiveDiscoveryClient discoveryClient;
            private final Environment environment;

            private LazyReactiveDiscoveryClientServiceInstanceListSupplier(ReactiveDiscoveryClient discoveryClient,
                                                                          Environment environment) {
                this.discoveryClient = discoveryClient;
                this.environment = environment;
            }

            @Override
            public String getServiceId() {
                return LoadBalancerClientFactory.getName(environment);
            }

            @Override
            public Flux<List<ServiceInstance>> get() {
                String serviceId = getServiceId();
                if (serviceId == null || serviceId.isBlank()) {
                    return Flux.just(List.of());
                }
                return discoveryClient.getInstances(serviceId).collectList().flux();
            }
        }

    }

}
