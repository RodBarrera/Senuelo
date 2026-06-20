"""Motor de admisión (control de alcance) de Señuelo.

El :class:`ScopeEngine` es el guardia de la plataforma. Antes de admitir cualquier
destinatario:

1. Verifica la firma de la autorización (si fue alterada, rechaza *todo*).
2. Comprueba que la autorización esté vigente (firmada, dentro de ventana, no
   revocada).
3. Para cada destinatario, en orden: formato válido → no excluido → dentro del
   alcance de dominios.

Toda decisión es explicable: el modo por lote devuelve un reporte con la lista
admitida y los rechazos con código y motivo, listos para el audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

from .errors import (
    AuthorizationNotActiveError,
    AuthorizationRevokedError,
    ExcludedRecipientError,
    MalformedRecipientError,
    OutOfScopeError,
)
from .models import Authorization, AuthorizationStatus
from .signing import verify

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


@dataclass(frozen=True)
class RecipientRejection:
    """Un destinatario rechazado, con su causa. Material directo de auditoría."""

    email: str
    code: str
    reason: str


@dataclass
class AdmissionReport:
    """Resultado de evaluar una lista de destinatarios contra una autorización."""

    admitted: list[str] = field(default_factory=list)
    rejected: list[RecipientRejection] = field(default_factory=list)

    @property
    def admitted_count(self) -> int:
        return len(self.admitted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def total(self) -> int:
        return self.admitted_count + self.rejected_count


def _extract_domain(email: str) -> str:
    """Extrae y valida el dominio de una dirección. Lanza si está malformada."""
    candidate = email.strip().lower()
    parts = candidate.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise MalformedRecipientError(f"dirección de correo inválida: {email!r}")
    domain = parts[1]
    if not _DOMAIN_RE.match(domain):
        raise MalformedRecipientError(f"dominio de correo inválido: {email!r}")
    return domain


class ScopeEngine:
    """Guardia de alcance para una autorización concreta."""

    def __init__(
        self,
        authorization: Authorization,
        key: str | bytes | None = None,
    ) -> None:
        self.authorization = authorization
        self._key = key

    # --- vigencia de la autorización ------------------------------------

    def ensure_valid(self, at: datetime | None = None) -> None:
        """Verifica firma y vigencia. Lanza el error tipado correspondiente."""
        # 1) Integridad: la firma se valida siempre primero.
        verify(self.authorization, self._key)
        # 2) Vigencia temporal / revocación.
        status = self.authorization.status(at)
        if status is AuthorizationStatus.REVOKED:
            raise AuthorizationRevokedError("la autorización fue revocada")
        if status is AuthorizationStatus.NOT_YET_ACTIVE:
            raise AuthorizationNotActiveError(
                "la autorización aún no entra en vigencia"
            )
        if status is AuthorizationStatus.EXPIRED:
            raise AuthorizationNotActiveError("la autorización ya expiró")

    # --- alcance de dominios --------------------------------------------

    def _domain_in_scope(self, domain: str) -> bool:
        for allowed in self.authorization.scope_domains:
            if domain == allowed:
                return True
            if self.authorization.include_subdomains and domain.endswith(
                "." + allowed
            ):
                return True
        return False

    # --- admisión individual --------------------------------------------

    def admit(self, email: str, at: datetime | None = None) -> str:
        """Admite un destinatario o lanza un :class:`ScopeError` con el motivo.

        Devuelve la dirección normalizada (minúsculas, sin espacios) si pasa.
        """
        self.ensure_valid(at)
        domain = _extract_domain(email)  # también valida el formato
        normalized = email.strip().lower()
        if self.authorization.is_excluded(normalized):
            raise ExcludedRecipientError(
                f"destinatario en lista de exclusión: {normalized}"
            )
        if not self._domain_in_scope(domain):
            raise OutOfScopeError(
                f"dominio fuera del alcance autorizado: {domain}"
            )
        return normalized

    # --- admisión por lote (auditable) ----------------------------------

    def filter_recipients(
        self,
        emails: list[str],
        at: datetime | None = None,
    ) -> AdmissionReport:
        """Evalúa una lista completa de destinatarios.

        Si la autorización no es válida (firma o vigencia), no admite a nadie:
        el error de autorización se propaga, porque es una falla del ejercicio
        entero, no de un destinatario.
        """
        self.ensure_valid(at)  # falla-cerrado a nivel de campaña
        report = AdmissionReport()
        for email in emails:
            try:
                report.admitted.append(self.admit(email, at))
            except (
                MalformedRecipientError,
                ExcludedRecipientError,
                OutOfScopeError,
            ) as exc:
                report.rejected.append(
                    RecipientRejection(
                        email=email.strip().lower(),
                        code=exc.code,
                        reason=exc.reason,
                    )
                )
        return report
