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
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.NettyWriteResponseFilter;
import org.springframework.cloud.gateway.filter.factory.cache.CachedResponse;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DefaultDataBuffer;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.springframework.cloud.gateway.filter.factory.cache.LocalResponseCacheGatewayFilterFactory.LOCAL_RESPONSE_CACHE_FILTER_APPLIED;

// Based on org.springframework.cloud.gateway.filter.factory.cache.ResponseCacheGatewayFilter
@Slf4j
public class WellKnownResponseCacheGatewayFilter implements GatewayFilter, Ordered {

    private static final List<HttpStatusCode> STATUSES_TO_CACHE =
            List.of(HttpStatus.OK, HttpStatus.PARTIAL_CONTENT, HttpStatus.MOVED_PERMANENTLY);

    private final WellKnownResponseCacheManager responseCacheManager;

    public WellKnownResponseCacheGatewayFilter(WellKnownResponseCacheManager responseCacheManager) {
        this.responseCacheManager = responseCacheManager;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        exchange = exchange.mutate()
                .request(sanitizeRequest(exchange.getRequest()))
                .build();
        if (!HttpMethod.GET.equals(exchange.getRequest().getMethod())) {
            log.debug("Skipping response caching, not a GET request");
            return chain.filter(exchange);
        }
        exchange.getAttributes().put(LOCAL_RESPONSE_CACHE_FILTER_APPLIED, true);
        exchange = exchange.mutate()
                .request(withoutBody(exchange.getRequest()))
                .build();
        String cacheKey = responseCacheManager.generateCacheKey(exchange.getRequest());
        Optional<CachedResponse> cached = responseCacheManager.getFromCache(cacheKey);
        if (cached.isPresent()) {
            log.debug("Response found in cache, returning cached response");
            return processFromCache(exchange, cached.get());
        }
        ServerWebExchange cachingExchange = exchange.mutate()
                .response(new CachingResponseDecorator(exchange.getResponse(), cacheKey))
                .build();
        return chain.filter(cachingExchange);
    }

    private Mono<Void> processFromCache(ServerWebExchange exchange, CachedResponse cachedResponse) {
        final ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(cachedResponse.statusCode());
        response.getHeaders().clear();
        response.getHeaders().addAll(cachedResponse.headers());
        Flux<DataBuffer> body = Flux.fromIterable(cachedResponse.body())
                .map(data -> response.bufferFactory().wrap(data));
        return response.writeWith(body);
    }

    private ServerHttpRequest sanitizeRequest(ServerHttpRequest request) {
        /* Query parameters are used as part of the cache key but are not relevant
         * for `.well-known` requests, so they can be removed. */
        URI sanitizedUri = UriComponentsBuilder.fromUri(request.getURI()).replaceQueryParams(null).build().toUri();
        return request
                .mutate()
                .uri(sanitizedUri)
                .headers(headers -> {
                    /* Authorization and Cookies headers are used as part of the cache key but are not relevant
                     * for `.well-known` requests, so they can be removed. */
                    headers.remove(HttpHeaders.AUTHORIZATION);
                    headers.remove(HttpHeaders.COOKIE);
                    /* Ignore client supplied caching preferences. */
                    headers.remove(HttpHeaders.CACHE_CONTROL);
                })
                .build();
    }

    private ServerHttpRequest withoutBody(ServerHttpRequest request) {
        return new WithoutBodyRequestDecorator(request);
    }

    @Override
    public int getOrder() {
        return NettyWriteResponseFilter.WRITE_RESPONSE_FILTER_ORDER - 3;
    }

    private class CachingResponseDecorator extends ServerHttpResponseDecorator {

        private final String cacheKey;

        CachingResponseDecorator(ServerHttpResponse delegate, String cacheKey) {
            super(delegate);
            this.cacheKey = cacheKey;
        }

        @Override
        public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
            HttpStatusCode statusCode = getStatusCode();
            if (!STATUSES_TO_CACHE.contains(statusCode)) {
                log.debug("Not storing response in cache, status code {}", statusCode);
                return super.writeWith(body);
            }
            if (getHeaders().containsKey(HttpHeaders.VARY)) {
                log.error("Unexpected {} header in response, not storing response in cache", HttpHeaders.VARY);
                return super.writeWith(body);
            }
            return super.writeWith(responseCacheManager.processFromUpstream(cacheKey, Flux.from(body), this));
        }

    }

    private static class WithoutBodyRequestDecorator extends ServerHttpRequestDecorator {

        public WithoutBodyRequestDecorator(ServerHttpRequest delegate) {
            super(delegate.mutate()
                    .headers(headers -> headers.remove(HttpHeaders.CONTENT_LENGTH))
                    .build());
        }

        @Override
        public Flux<DataBuffer> getBody() {
            DefaultDataBuffer dataBuffer = new DefaultDataBufferFactory().allocateBuffer(0);
            return super.getBody().map(ignored -> dataBuffer);
        }
    }


}
