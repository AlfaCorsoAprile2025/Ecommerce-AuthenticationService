package com.ecommerce.auth.exception;

import org.springframework.http.HttpStatus;


public class AuthException extends RuntimeException {

    private final HttpStatus status;

    public AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }

    // --- Eccezioni specifiche ---

    /** Email già registrata nel sistema. → 409 Conflict */
    public static class EmailAlreadyExistsException extends AuthException {
        public EmailAlreadyExistsException(String message) {
            super(message, HttpStatus.CONFLICT);
        }
    }

    /** Credenziali errate (email o password). → 401 Unauthorized
     *  NOTA: messaggio volutamente generico per non rivelare se l'email esiste. */
    public static class InvalidCredentialsException extends AuthException {
        public InvalidCredentialsException() {
            super("Credenziali non valide", HttpStatus.UNAUTHORIZED);
        }
    }

    /** Account disabilitato dall'admin. → 401 Unauthorized */
    public static class AccountDisabledException extends AuthException {
        public AccountDisabledException() {
            super("Account disabilitato", HttpStatus.UNAUTHORIZED);
        }
    }


    /** Token JWT non valido o scaduto. → 401 */
    public static class InvalidTokenException extends AuthException {
        public InvalidTokenException(String message) {
            super(message, HttpStatus.UNAUTHORIZED);
        }
    }

    /** Risorsa non trovata. → 404 */
    public static class NotFoundException extends AuthException {
        public NotFoundException(String message) {
            super(message, HttpStatus.NOT_FOUND);
        }
    }

    /** Account registrato ma in attesa di verifica OTP. → 403 Forbidden */
    public static class AccountNotActivatedException extends AuthException {
        public AccountNotActivatedException() {
            super("Account non attivato. Controlla la tua email e inserisci il codice OTP.", HttpStatus.FORBIDDEN);
        }
    }

    /** OTP non valido o già utilizzato. → 400 Bad Request */
    public static class InvalidOtpException extends AuthException {
        public InvalidOtpException() {
            super("Codice OTP non valido.", HttpStatus.BAD_REQUEST);
        }
    }

    /** OTP scaduto (TTL 5 minuti). → 400 Bad Request */
    public static class OtpExpiredException extends AuthException {
        public OtpExpiredException() {
            super("Codice OTP scaduto. Richiedi una nuova registrazione.", HttpStatus.BAD_REQUEST);
        }
    }

    /** Ruolo insufficiente per l'operazione richiesta. → 403 Forbidden */
    public static class AccessDeniedException extends AuthException {
        public AccessDeniedException(String message) {
            super(message, HttpStatus.FORBIDDEN);
        }
    }
}
