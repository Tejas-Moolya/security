package com.jwt.security.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

import com.jwt.security.bean.AuthenticationRequest;
import com.jwt.security.bean.AuthenticationResponse;
import com.jwt.security.bean.RegisterRequest;
import com.jwt.security.entity.Role;
import com.jwt.security.entity.Users;
import com.jwt.security.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

	private final UserRepository userRepo = null;

	private final JwtService jwtService = null;

	private final AuthenticationManager authenticationManager = null;

	public AuthenticationResponse register(RegisterRequest request) {
		Users user = new Users();
		user.setFirstName(request.getFirstName());
		user.setLastName(request.getLastName());
		user.setEmail(request.getEmail());
		user.setPassword(request.getPassword());
		user.setRole(Role.USER);
		userRepo.save(user);

		String token = jwtService.generateToken(user);

		AuthenticationResponse auth = new AuthenticationResponse();
		auth.setToken(token);
		return auth;
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

		Users user = userRepo.findByEmail(request.getEmail()).orElseThrow();

		String token = jwtService.generateToken(user);

		AuthenticationResponse auth = new AuthenticationResponse();
		auth.setToken(token);
		return auth;

	}

}
