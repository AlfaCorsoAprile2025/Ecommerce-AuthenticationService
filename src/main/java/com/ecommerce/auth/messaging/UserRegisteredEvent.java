package com.ecommerce.auth.messaging;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

/**
 * UserRegisteredEvent — messaggio pubblicato su RabbitMQ dopo la registrazione.
 *
 * DECISIONE ARCHITETTURALE (comunicazione asincrona):
 * La registrazione in AuthorizationService salva solo email + passwordHash (credenziali).
 * L'anagrafica (nome, cognome) è di competenza dello UserService.
 * Questo evento porta tutti i dati necessari allo UserService per creare
 * il record nel proprio DB, mantenendo i due servizi completamente disaccoppiati.
 *
 * Se lo UserService è temporaneamente down, il messaggio rimane in coda
 * e verrà processato al suo riavvio → resilienza.
 *
 * SCELTA DATI: inviamo solo lo stretto necessario. Nessuna password,
 * nessun dato sensibile oltre il minimo richiesto.
 */
@Data
@Builder
public class UserRegisteredEvent {

    /** Correlation ID per tracing distribuito. */
    private String eventId;

    /** Timestamp di creazione evento — per deduplicazione e ordering. */
    private Instant occurredAt;

    /** ID generato in AuthorizationService — sarà la chiave condivisa tra i servizi. */
    private String userId;

    private String email;
    private String firstName;
    private String lastName;

    /** Ruolo iniziale assegnato — default "USER". */
    private String initialRole;

    /**
     * OTP in chiaro — consumato dal mailing service per inviare l'email di verifica.
     * Non viene mai persistito in questo servizio (qui si conserva solo l'hash).
     */
    private String otpCode;
}
