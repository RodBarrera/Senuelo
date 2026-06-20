"""Motor de alcance y autorización de Señuelo.

Núcleo ético de la plataforma: nada se envía sin una autorización firmada y
vigente, y cada destinatario admitido lo es contra un alcance explícito.
"""

from .engine import AdmissionReport, RecipientRejection, ScopeEngine
from .errors import (
    AuthorizationNotActiveError,
    AuthorizationRevokedError,
    ExcludedRecipientError,
    InvalidSignatureError,
    MalformedRecipientError,
    OutOfScopeError,
    ScopeError,
)
from .models import Authorization, AuthorizationStatus, Party
from .signing import compute_signature, sign, verify

__all__ = [
    "Authorization",
    "AuthorizationStatus",
    "Party",
    "ScopeEngine",
    "AdmissionReport",
    "RecipientRejection",
    "sign",
    "verify",
    "compute_signature",
    "ScopeError",
    "InvalidSignatureError",
    "AuthorizationNotActiveError",
    "AuthorizationRevokedError",
    "OutOfScopeError",
    "ExcludedRecipientError",
    "MalformedRecipientError",
]
