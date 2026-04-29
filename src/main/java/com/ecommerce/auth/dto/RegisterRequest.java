package com.ecommerce.auth.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

/**
 * DTO di registrazione — mappa la request POST /register.
 *
 * DECISIONE: DTO separato dal modello di dominio.
 * Il controller non riceve mai un oggetto Credentials direttamente:
 * evita binding accidentale di campi interni (es. passwordHash, enabled).
 */
@Data
public class RegisterRequest {

    @NotBlank(message = "Email obbligatoria")
    @Email(message = "Formato email non valido")
    private String email;

    @NotBlank(message = "Password obbligatoria")
    @Size(min = 8, max = 32, message = "Password: 8-32 caratteri")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
        message = "Password deve contenere maiuscola, minuscola, numero e carattere speciale"
    )
    private String password;

    @NotBlank(message = "Nome obbligatorio")
    @Size(min = 1, max = 100)
    private String firstName;

    @NotBlank(message = "Cognome obbligatorio")
    @Size(min = 1, max = 100)
    private String lastName;
}
