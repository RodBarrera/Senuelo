"""Configuración de la API de Señuelo.

Todo lo sensible se lee del entorno del servidor, nunca del cliente ni del
código fuente:

- ``SENUELO_SIGNING_KEY``: clave HMAC para firmar autorizaciones (obligatoria
  para operar con autorizaciones).
- ``SENUELO_API_KEY``: si está definida, la API exige el header ``X-API-Key``.
  Si no está, la API corre en *modo dev* abierto y lo advierte en los logs.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger("senuelo.api")


@dataclass(frozen=True)
class Settings:
    signing_key: str | None
    api_key: str | None
    db_path: str | None

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key)

    @property
    def signing_enabled(self) -> bool:
        return bool(self.signing_key)

    @property
    def persistence_enabled(self) -> bool:
        return bool(self.db_path)


@lru_cache
def get_settings() -> Settings:
    settings = Settings(
        signing_key=os.environ.get("SENUELO_SIGNING_KEY"),
        api_key=os.environ.get("SENUELO_API_KEY"),
        db_path=os.environ.get("SENUELO_DB_PATH"),
    )
    if not settings.signing_enabled:
        logger.warning(
            "SENUELO_SIGNING_KEY no está definida: los endpoints de "
            "autorización fallarán hasta configurarla."
        )
    if not settings.auth_enabled:
        logger.warning(
            "SENUELO_API_KEY no está definida: la API corre en modo dev "
            "ABIERTO, sin autenticación. No usar así fuera de desarrollo."
        )
    if not settings.persistence_enabled:
        logger.warning(
            "SENUELO_DB_PATH no está definida: persistencia en memoria; "
            "las autorizaciones y el audit log se pierden al reiniciar."
        )
    return settings
