package com.ecommerce.auth.config;

import com.ecommerce.auth.security.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

import java.util.List;

@Configuration
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(List.of("*")); // Permette tutti i siti
                    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE","PATCH"));
                    config.setAllowedHeaders(List.of("*"));
                    return config;
                }))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                // Stateless: nessuna sessione server-side
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                .authorizeExchange(exchanges -> exchanges
                        // Endpoint pubblici — accessibili senza token
                        .pathMatchers(HttpMethod.POST, "/auth/hash-password").permitAll()
                        .pathMatchers(HttpMethod.POST, "/auth/login").permitAll()
                        // Actuator health — accessibile per health check del cluster
                        .pathMatchers("/actuator/health").permitAll()
                        // Tutto il resto richiede autenticazione
                        .anyExchange().authenticated()
                )
                // Inserisce il filtro JWT prima del filtro di autenticazione standard
                .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                // Disabilita form login e HTTP Basic (non pertinenti per API REST)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
