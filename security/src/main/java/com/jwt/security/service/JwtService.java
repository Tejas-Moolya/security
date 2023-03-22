package com.jwt.security.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.jwt.security.entity.Users;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private static final String secretKey="753778214125442A472D4B6150645367566B59703373367639792F423F452848";
	
	public String extractUserName(String token) {

		return extractClaim(token,Claims::getSubject);
	}
	
	public <T> T extractClaim(String token, Function<Claims, T> claimsresolver){
		final Claims claims=extractAllClaims(token);
		return claimsresolver.apply(claims);
	}

	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignInKey()).build().parseClaimsJws(token).getBody();
	}

	private Key getSignInKey() {
		byte[] key=Decoders.BASE64.decode(secretKey);
		
		return Keys.hmacShaKeyFor(key);
	}
	
	public boolean isTokenValid(String token, UserDetails userDetailsService) {
		
		final String username=extractUserName(token);
		return(username.equals(userDetailsService.getUsername()) && !isTokenValid(token, userDetailsService)) && isTokenExpired(token);
	}
	
	
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	public String generateToken(Map<String, Object> extractClaims, UserDetails userDetails) {
		
		return Jwts.builder()
				.setClaims(extractClaims)
				.setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000 *60 *24))
				.signWith(getSignInKey(),SignatureAlgorithm.HS256)
				.compact();
	}

	public String generateToken(Users user) {
		return generateToken(new HashMap<>(),user);
	}

}
