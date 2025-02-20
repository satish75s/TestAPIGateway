package com.gateway.filter;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;
import reactor.core.publisher.Mono;

@Component
public class JwtRoleCheckFilter extends AbstractGatewayFilterFactory<JwtRoleCheckFilter.Config> {

	private static final Logger logger = LoggerFactory.getLogger(JwtRoleCheckFilter.class);
	private static final String SECRET_KEY = "S2z1S14+9abMcwzKmoYWuA4RyV1ip1Pp013bKRc2bML6s7d0w0IbP5A+P+zP/ntVhHnlUC1fc0IG0HNPL/GA6w=="; // JWT
																																			// Secret
																																			// Key

	@Autowired
	RouteValidator validator;

	public JwtRoleCheckFilter() {
		super(Config.class);
	}

	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {

			if (validator.isSecured.test(exchange.getRequest())) {// Extract required role from the config
				String requiredRole = config.getRequiredRole();

				if (requiredRole != null) {
					logger.info("Required Role from Config: {}", requiredRole);

					// Get the JWT token from the Authorization header
					String token = exchange.getRequest().getHeaders().getFirst("Authorization");
					if (token == null || !token.startsWith("Bearer ")) {
						logger.warn("Missing or invalid token");
						return unauthorizedResponse(exchange, "Missing or invalid token");
					}

					String jwt = token.substring(7); // Remove "Bearer " prefix

					try {
						List<String> roles = extractRolesFromJwt(jwt);
						logger.info("Extracted Roles: {}", roles);

						// Check if the user has the required role
						if (hasRequiredRole(roles, requiredRole)) {
							logger.info("Access granted for required role: {}", requiredRole);
							return chain.filter(exchange);
						} else {
							logger.warn("Insufficient permissions. Required: {}, Found: {}", requiredRole, roles);
							return unauthorizedResponse(exchange, "Insufficient permissions");
						}
					} catch (SignatureException e) {
						logger.error("Invalid JWT signature", e);
						return unauthorizedResponse(exchange, "Invalid token");
					} catch (Exception e) {
						logger.error("Error processing JWT", e);
						return unauthorizedResponse(exchange, "Error processing token");
					}
				} else {
					logger.warn("Required role not found in the config");
					return unauthorizedResponse(exchange, "Missing required role configuration");
				}
			} else {
				return chain.filter(exchange);
			}

		};
	}

	private boolean hasRequiredRole(List<String> roles, String requiredRole) {
		String[] requiredRoles = requiredRole.split(",");
		for (String role : requiredRoles) {
			if (roles.contains(role.trim())) {
				return true;
			}
		}
		return false;
	}

	private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		exchange.getResponse().getHeaders().add("Content-Type", "application/json");
		return exchange.getResponse().writeWith(Mono
				.just(exchange.getResponse().bufferFactory().wrap(("{\"error\": \"" + message + "\"}").getBytes())));
	}

	private List<String> extractRolesFromJwt(String jwt) {
		Claims claims = Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(jwt).getPayload();

		@SuppressWarnings("unchecked")
		List<Map<String, String>> rolesClaim = (List<Map<String, String>>) claims.get("roles");
		return rolesClaim.stream().map(role -> role.get("authority")).collect(Collectors.toList());
	}

	private SecretKey getKey() {
		byte[] keyBytes = java.util.Base64.getDecoder().decode(SECRET_KEY);
		return new SecretKeySpec(keyBytes, "HmacSHA512");
	}

	public static class Config {
		private String requiredRole;

		// Default constructor
		public Config() {
		}

		// Constructor with requiredRole parameter
		public Config(String requiredRole) {
			this.requiredRole = requiredRole;
		}

		public String getRequiredRole() {
			return requiredRole;
		}

		public void setRequiredRole(String requiredRole) {
			this.requiredRole = requiredRole;
		}
	}
}