package com.klawund.identity.auth;

import com.klawund.identity.jwt.JwtService;
import com.klawund.identity.user.Role;
import com.klawund.identity.user.User;
import com.klawund.identity.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService
{
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest request)
	{
		var user = User.builder()
			.firstName(request.getFirstName())
			.lastName(request.getLastName())
			.email(request.getEmail())
			.password(passwordEncoder.encode(request.getPassword()))
			.role(Role.USER)
			.build();

		userService.save(user);

		var jwt = jwtService.generateToken(user);
		return AuthenticationResponse.builder()
			.token(jwt)
			.build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request)
	{
		authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(
				request.getEmail(),
				request.getPassword())
		);

		var user = userService.loadUserByUsername(request.getEmail());

		var jwt = jwtService.generateToken(user);
		return AuthenticationResponse.builder()
			.token(jwt)
			.build();
	}
}
