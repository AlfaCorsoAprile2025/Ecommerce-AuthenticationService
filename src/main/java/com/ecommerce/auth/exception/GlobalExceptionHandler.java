package com.ecommerce.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.stream.Collectors;


@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /** Gestisce tutte le AuthException del dominio */
    @ExceptionHandler(AuthException.class)
    public Mono<ResponseEntity<Map<String, String>>> handleAuthException(AuthException ex) {
        log.debug("[ExceptionHandler] AuthException: {} → {}", ex.getClass().getSimpleName(), ex.getMessage());
        return Mono.just(ResponseEntity
                .status(ex.getStatus())
                .body(errorBody(ex.getClass().getSimpleName(), ex.getMessage())));
    }

    /** Gestisce errori di validazione Bean Validation (@Valid) */
    @ExceptionHandler(WebExchangeBindException.class)
    public Mono<ResponseEntity<Map<String, Object>>> handleValidation(WebExchangeBindException ex) {
        Map<String, String> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        fe -> fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "Valore non valido",
                        (a, b) -> a
                ));
        return Mono.just(ResponseEntity
                .badRequest()
                .body(Map.of(
                        "code", "VALIDATION_ERROR",
                        "message", "Dati non validi",
                        "fields", fieldErrors
                )));
    }

    /** Fallback per eccezioni non previste */
    @ExceptionHandler(Exception.class)
    public Mono<ResponseEntity<Map<String, String>>> handleGeneric(Exception ex) {
        log.error("[ExceptionHandler] Errore non gestito", ex);
        return Mono.just(ResponseEntity
                .internalServerError()
                .body(errorBody("INTERNAL_ERROR", "Si è verificato un errore interno")));
    }

    private Map<String, String> errorBody(String code, String message) {
        return Map.of("code", code, "message", message);
    }
}
