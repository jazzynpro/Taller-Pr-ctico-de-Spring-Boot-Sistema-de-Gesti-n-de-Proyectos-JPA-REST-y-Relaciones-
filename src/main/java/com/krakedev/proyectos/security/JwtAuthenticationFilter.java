package com.krakedev.proyectos.security;

import java.io.*;
import java.util.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.proyectos.services.TokenBlacklistService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final TokenBlacklistService tokenBlacklistService;

	public JwtAuthenticationFilter(TokenBlacklistService tokenBlacklistService) {
		this.tokenBlacklistService = tokenBlacklistService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String authHeader = request.getHeader("Authorization");
		System.out.println("HEADER RECIBIDO: " + authHeader);

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = authHeader.substring(7);

		if (tokenBlacklistService.estaInvalidado(token)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			response.getWriter().write("Acceso denegado: Sesion Cerrada");
			return;
		}

		DecodedJWT datosToken = JwtUtil.validarToken(token);

		if (datosToken != null) {
			String username = datosToken.getSubject();
			String rolOriginal = datosToken.getClaim("rol").asString();

			String rolSpring = "ROLE_" + rolOriginal;

			SimpleGrantedAuthority authority = new SimpleGrantedAuthority(rolSpring);

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null,
					Collections.singleton(authority));

			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		filterChain.doFilter(request, response);
	}
}