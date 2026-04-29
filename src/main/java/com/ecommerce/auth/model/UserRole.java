package com.ecommerce.auth.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

/**
 * UserRole — Associazione credentials ↔ ruolo RBAC.
 *
 * DECISIONE: tabella separata (non colonna JSON) per permettere
 * query efficienti su ruolo e futura espansione (es. permessi per ruolo).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("user_roles")
public class UserRole {

    /** PK surrogata — generata dal DB, non usata dalla logica applicativa. */
    @Id
    private Long id;

    /** FK logica verso Credentials._id in MongoDB. */
    private String credentialId;

    private String role;
}
