package com.gateway.util;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {

	public String SECRET = "FFfrrXM7zzb6BKjBIGCV0wOLbUYya50la6iJBYvB21o=";

	/*
	 * public JwtUtil() {
	 * 
	 * try { KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256"); SecretKey
	 * sk = keyGen.generateKey(); SECRET =
	 * Base64.getEncoder().encodeToString(sk.getEncoded()); } catch
	 * (NoSuchAlgorithmException e) { throw new RuntimeException(e); } }
	 */

	public boolean validateToken(String token, String username) {
		final String userName = extractUserName(token);
		// return (userName.equals("admin") && !isTokenExpired(token));
		return (!isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
	}

	private SecretKey getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}