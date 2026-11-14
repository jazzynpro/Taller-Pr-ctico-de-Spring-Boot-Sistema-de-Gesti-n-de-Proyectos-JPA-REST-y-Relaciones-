package com.krakedev.proyectos.services;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class TokenBlacklistService {
	// Lista negra segura para entornos concurrentes (multi-hilo)
	private final Set<String> blacklist = ConcurrentHashMap.newKeySet();

	public void addToken(String token) {
		blacklist.add(token);
	}

	// Método que requiere tu filtro
    public boolean estaInvalidado(String token) {
        return blacklist.contains(token);
    }
}
