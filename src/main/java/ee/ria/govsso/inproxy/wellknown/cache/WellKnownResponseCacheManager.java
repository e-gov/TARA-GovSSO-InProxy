/*
 * Copyright 2013-2022 the original author or authors.
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

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cloud.gateway.filter.factory.cache.CachedResponse;
import org.springframework.cloud.gateway.filter.factory.cache.keygenerator.CacheKeyGenerator;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Flux;

import java.nio.ByteBuffer;
import java.util.Optional;

//Based on org.springframework.cloud.gateway.filter.factory.cache.ResponseCacheManager
@Slf4j
public class WellKnownResponseCacheManager {

	private final CacheKeyGenerator cacheKeyGenerator;
	private final Cache cache;

	public WellKnownResponseCacheManager(CacheKeyGenerator cacheKeyGenerator, Cache cache) {
		this.cacheKeyGenerator = cacheKeyGenerator;
		this.cache = cache;
	}

	public String generateCacheKey(ServerHttpRequest request) {
		return cacheKeyGenerator.generateKey(request);
	}


	public Flux<DataBuffer> processFromUpstream(String cacheKey, Flux<DataBuffer> body, ServerHttpResponse response) {
		CachedResponse.Builder cachedResponseBuilder = CachedResponse.create(response.getStatusCode())
				.headers(response.getHeaders());

		return body.map(dataBuffer -> {
			ByteBuffer byteBuffer = dataBuffer.toByteBuffer().asReadOnlyBuffer();
			cachedResponseBuilder.appendToBody(byteBuffer);
			return dataBuffer;
		}).doOnComplete(() -> {
			CachedResponse responseToCache = cachedResponseBuilder.build();
			saveInCache(cacheKey, responseToCache);
		});
	}

	public Optional<CachedResponse> getFromCache(String key) {
		try {
			return Optional.ofNullable(cache.get(key, CachedResponse.class));
		} catch (RuntimeException anyException) {
			log.error("Error reading from cache. Data will not come from cache.", anyException);
			return Optional.empty();
		}
	}

	private void saveInCache(String cacheKey, CachedResponse cachedResponse) {
		try {
			cache.put(cacheKey, cachedResponse);
		} catch (RuntimeException anyException) {
			log.error("Error writing into cache. Data will not be cached", anyException);
		}
	}

}
