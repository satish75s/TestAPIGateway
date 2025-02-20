package com.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.gateway.filter.JwtRoleCheckFilter;

@Configuration
public class GatewayConfig {

    private final JwtRoleCheckFilter jwtRoleCheckFilter;

    public GatewayConfig(JwtRoleCheckFilter jwtRoleCheckFilter) {
        this.jwtRoleCheckFilter = jwtRoleCheckFilter;
    }

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                // Super Admin Route
                .route("super-admin-route", r -> r.path("/target/sadmin")
                        .filters(f -> f.filter(jwtRoleCheckFilter.apply(new JwtRoleCheckFilter.Config("ROLE_USER,ROLE_ADMIN"))))
                        .uri("lb://TARGETSERVICE"))
                
                // User Route
                .route("user-route", r -> r.path("/target/user")
                        .filters(f -> f.filter(jwtRoleCheckFilter.apply(new JwtRoleCheckFilter.Config("ROLE_USER"))))
                        .uri("lb://TARGETSERVICE"))
                
                // Admin Route
                .route("admin-route", r -> r.path("/target/admin")
                        .filters(f -> f.filter(jwtRoleCheckFilter.apply(new JwtRoleCheckFilter.Config("ROLE_ADMIN"))))
                        .uri("lb://TARGETSERVICE"))
                
                // All Route (No role required)
                .route("all-route", r -> r.path("/target/all")
                        .filters(f -> f.filter(jwtRoleCheckFilter.apply(new JwtRoleCheckFilter.Config())))
                        .uri("lb://TARGETSERVICE"))

                // AuthService Route
                .route("AUTHSERVICE", r -> r.path("/auth/**")
                        .uri("lb://AUTHSERVICE"))
                
                .build();
    }
}