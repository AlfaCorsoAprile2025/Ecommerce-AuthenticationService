package com.ecommerce.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

/**
 * Regola RBAC per un endpoint: associa un metodo HTTP + pattern URI ai ruoli che possono eseguirlo.
 *
 * requiredRoles vuoto  → qualsiasi utente autenticato è autorizzato.
 * requiredRoles non vuoto → l'utente deve possedere almeno uno dei ruoli elencati.
 *
 * Politica di default: se nessuna regola corrisponde → 403 (deny by default).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Document("route_permissions")
public class RoutePermission {

    @Id
    private String id;

    /** Metodo HTTP in maiuscolo: "GET", "POST", "PUT", "DELETE", "PATCH". */
    private String httpMethod;

    /** Pattern Ant: es. "/catalog/products/**", "/catalog/products/{id}". */
    private String uriPattern;

    /** Ruoli autorizzati. Lista vuota = qualsiasi utente autenticato. */
    private List<String> requiredRoles;

    /** Descrizione human-readable della regola (documentazione). */
    private String description;
}
