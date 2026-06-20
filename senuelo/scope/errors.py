"""Errores del motor de alcance (scope) de Señuelo.

Filosofía: *fail-closed*. Toda denegación es explícita, tipada y portadora de
un motivo legible, porque ese motivo es exactamente lo que alimenta el audit
log inmutable. Nunca se deniega "en silencio" ni se admite "por las dudas".
"""

from __future__ import annotations


class ScopeError(Exception):
    """Base de todos los errores de alcance/autorización.

    Atributos:
        reason: motivo legible, pensado para registrarse en el audit log.
    """

    #: Código corto y estable para clasificar el evento en métricas/auditoría.
    code: str = "scope_error"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class InvalidSignatureError(ScopeError):
    """La firma de la autorización no valida: fue alterada o usa otra clave."""

    code = "invalid_signature"


class AuthorizationNotActiveError(ScopeError):
    """La campaña intenta operar fuera de la ventana temporal autorizada."""

    code = "authorization_not_active"


class AuthorizationRevokedError(ScopeError):
    """La autorización fue revocada y ya no habilita ninguna acción."""

    code = "authorization_revoked"


class OutOfScopeError(ScopeError):
    """El destinatario no pertenece a ningún dominio dentro del alcance."""

    code = "out_of_scope"


class ExcludedRecipientError(ScopeError):
    """El destinatario está en la lista de exclusión (opt-out / no-objetivo)."""

    code = "excluded_recipient"


class MalformedRecipientError(ScopeError):
    """La dirección de correo no es válida y no puede evaluarse."""

    code = "malformed_recipient"
