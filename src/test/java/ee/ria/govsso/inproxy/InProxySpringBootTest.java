package ee.ria.govsso.inproxy;

import ee.ria.govsso.inproxy.configuration.TestLoadBalancingConfiguration;
import ee.ria.govsso.inproxy.configuration.TestSchedulingConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@SpringBootTest(
        webEnvironment = RANDOM_PORT,
        classes = {
                Application.class,
                MockPropertyBeanConfiguration.class,
                TestLoadBalancingConfiguration.class,
                TestSchedulingConfiguration.class
        })
public @interface InProxySpringBootTest {
}
