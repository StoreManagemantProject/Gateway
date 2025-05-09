package com.example.demo.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.demo.util.Authorization;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;

    private final List<String> excludedPaths = Arrays.asList(
        "/auth/public/**",
        "/public/",
        "/actuator/health"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (excludedPaths.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        try {
            String token = extractToken(exchange.getRequest());
            if (token == null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            DecodedJWT jwt = validateToken(token);
            
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Email", jwt.getClaim("email").asString())
                .header("X-User-Roles", String.join(",", jwt.getClaim("roles").asArray(String.class)))
                .header("X-User-Type", jwt.getClaim("type").asString())
                .header("X-User-Id", jwt.getClaim("id").asString())
                .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (JWTVerificationException e) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
            return exchange.getResponse().setComplete();
        }
    }

    private String extractToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private DecodedJWT validateToken(String token) throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) Authorization.getPublicKey(publicKeyPath);
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        
        return JWT.require(algorithm)
                .withIssuer("store_app")
                .build()
                .verify(token);
    }

    @Override
    public int getOrder() {
        return -100; 
    }
}