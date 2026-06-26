package ee.ria.govsso.inproxy.logging;

import com.fasterxml.jackson.annotation.JsonInclude;
import net.logstash.logback.decorate.MapperBuilderDecorator;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.util.StdDateFormat;

public class LogbackMapperBuilderDecorator implements MapperBuilderDecorator<JsonMapper, JsonMapper.Builder> {

    @Override
    public JsonMapper.Builder decorate(JsonMapper.Builder builder) {
        return builder
                .defaultDateFormat(new StdDateFormat().withColonInTimeZone(false))
                .changeDefaultPropertyInclusion(inclusion -> inclusion.withValueInclusion(JsonInclude.Include.NON_NULL))
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
    }
}
