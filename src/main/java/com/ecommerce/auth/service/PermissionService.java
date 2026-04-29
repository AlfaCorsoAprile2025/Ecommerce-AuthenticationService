package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.AuthContext;
import com.ecommerce.auth.exception.AuthException;
import com.ecommerce.auth.repository.RoutePermissionRepository;
import com.ecommerce.auth.security.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final TokenProvider tokenProvider;
    private final RoutePermissionRepository routePermissionRepository;
    private final PathPatternParser patternParser = new PathPatternParser();

    /**
     * Verifica che il token sia valido e che l'utente abbia i permessi per METHOD + URI.
     *
     * Lancia InvalidTokenException (401) se il JWT non è valido o scaduto.
     * Lancia AccessDeniedException (403) se nessuna regola corrisponde o il ruolo non è sufficiente.
     */
    public Mono<AuthContext> checkPermission(String token, String uri, String method) {
        return tokenProvider.validateAccessToken(token)
                .onErrorMap(e -> new AuthException.InvalidTokenException("Token non valido o scaduto"))
                .flatMap(claims -> {
                    String userId = claims.getSubject();
                    List<String> userRoles = tokenProvider.extractRoles(claims);

                    return routePermissionRepository
                            .findByHttpMethod(method.toUpperCase())
                            .filter(perm -> matches(perm.getUriPattern(), uri))
                            .next()
                            .switchIfEmpty(Mono.error(new AuthException.AccessDeniedException(
                                    "Nessuna regola definita per " + method + " " + uri)))
                            .flatMap(perm -> {
                                List<String> required = perm.getRequiredRoles();
                                if (required != null && !required.isEmpty()
                                        && required.stream().noneMatch(userRoles::contains)) {
                                    log.warn("[validate] Accesso negato userId={} roles={} → {} {}",
                                            userId, userRoles, method, uri);
                                    return Mono.error(new AuthException.AccessDeniedException(
                                            "Ruolo insufficiente per " + method + " " + uri));
                                }
                                String primaryRole = (userRoles != null && !userRoles.isEmpty())
                                        ? userRoles.get(0) : "USER";
                                log.debug("[validate] Autorizzato userId={} role={} → {} {}",
                                        userId, primaryRole, method, uri);
                                return Mono.just(new AuthContext(userId, primaryRole));
                            });
                });
    }

    private boolean matches(String pattern, String uri) {
        try {
            return patternParser.parse(pattern).matches(PathContainer.parsePath(uri));
        } catch (Exception e) {
            log.debug("[validate] Pattern non valido '{}': {}", pattern, e.getMessage());
            return false;
        }
    }
}
