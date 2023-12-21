/*
 * Copyright 2013-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ee.ria.govsso.inproxy.wellknown.cache;

import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.cache.Cache;
import org.springframework.cloud.gateway.config.LocalResponseCacheAutoConfiguration;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.cloud.gateway.filter.factory.cache.LocalResponseCacheProperties;
import org.springframework.cloud.gateway.filter.factory.cache.keygenerator.CacheKeyGenerator;
import org.springframework.cloud.gateway.support.HasRouteId;
import org.springframework.stereotype.Component;
import org.springframework.util.unit.DataSize;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

// Based on org.springframework.cloud.gateway.filter.factory.cache.LocalResponseCacheGatewayFilterFactory
@Component
public class WellKnownResponseCacheGatewayFilterFactory
		extends AbstractGatewayFilterFactory<WellKnownResponseCacheGatewayFilterFactory.RouteCacheConfiguration> {

	private final CacheKeyGenerator cacheKeyGenerator;

	public WellKnownResponseCacheGatewayFilterFactory(CacheKeyGenerator cacheKeyGenerator) {
		super(WellKnownResponseCacheGatewayFilterFactory.RouteCacheConfiguration.class);
		this.cacheKeyGenerator = cacheKeyGenerator;
	}

	@Override
	public GatewayFilter apply(RouteCacheConfiguration config) {
		LocalResponseCacheProperties cacheProperties = mapRouteCacheConfig(config);

		Cache cache = LocalResponseCacheAutoConfiguration.createGatewayCacheManager(cacheProperties)
				.getCache(config.getRouteId() + "-well-known-cache");
		return new WellKnownResponseCacheGatewayFilter(new WellKnownResponseCacheManager(cacheKeyGenerator, cache));
	}

	private LocalResponseCacheProperties mapRouteCacheConfig(RouteCacheConfiguration config) {

		LocalResponseCacheProperties responseCacheProperties = new LocalResponseCacheProperties();
		responseCacheProperties.setTimeToLive(config.getTimeToLive());
		responseCacheProperties.setSize(config.getSize());
		return responseCacheProperties;
	}

	@Override
	public List<String> shortcutFieldOrder() {
		return List.of("timeToLive", "size");
	}

	@Validated
	@Data
	public static class RouteCacheConfiguration implements HasRouteId {

		@NotNull private DataSize size;
		@NotNull private Duration timeToLive;
		private String routeId;

	}

}
