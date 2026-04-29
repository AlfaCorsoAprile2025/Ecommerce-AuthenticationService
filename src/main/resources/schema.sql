-- user_roles: associazione credentials (MongoDB _id) ↔ ruolo RBAC
-- IF NOT EXISTS rende lo script idempotente: sicuro eseguirlo ad ogni avvio
CREATE TABLE IF NOT EXISTS user_roles (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    credential_id VARCHAR(64) NOT NULL,
    role          VARCHAR(50) NOT NULL,
    CONSTRAINT uq_credential_role UNIQUE (credential_id, role)
);
