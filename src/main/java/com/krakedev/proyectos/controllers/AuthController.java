package com.krakedev.proyectos.controllers;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.krakedev.proyectos.entidades.Usuario;
import com.krakedev.proyectos.services.TokenBlacklistService;
import com.krakedev.proyectos.services.UsuarioService;
import com.krakedev.proyectos.repositories.UsuarioRepository;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final UsuarioService usuarioService;
    private final UsuarioRepository usuarioRepository;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository, TokenBlacklistService tokenBlacklistService) {
        this.usuarioService = usuarioService;
        this.usuarioRepository = usuarioRepository;
        this.tokenBlacklistService = tokenBlacklistService;
    }
    
    @PostMapping("/registrar")
    public ResponseEntity<?> registrar(@RequestBody Usuario usuario) {
        try {
            Usuario usuarioNuevo = usuarioService.registrar(usuario);
            return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al registrar usuario: " + e.getMessage());
        }
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Usuario usuario) {
        String username = usuario.getUsername();
        String password = usuario.getPassword();
        
        boolean autenticado = usuarioService.autenticar(username, password);
        
        if (autenticado) {
            return ResponseEntity.ok(Map.of("mensaje", "Autenticación exitosa (Token pendiente para el Hito 2)"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrecta");
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Error: Debes proveer un token Bearer válido en la cabecera Authorization");
        }
        
        // Extraemos el token quitando la palabra "Bearer " (primeros 7 caracteres)
        String token = authHeader.substring(7);
        tokenBlacklistService.addToken(token);
        
        return ResponseEntity.ok(Map.of("mensaje", "Logout exitoso. El token ha sido invalidado."));
    }
    
    @GetMapping
    public ResponseEntity<?> listarUsuarios() {
        try {
            List<Usuario> usuarios = usuarioRepository.findAll();
            return ResponseEntity.ok(usuarios);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error al listar usuarios: " + e.getMessage());
        }
    }
    
}