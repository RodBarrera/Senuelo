"""Dependencias de la API."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from .config import get_settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Exige el header ``X-API-Key`` si el servidor configuró ``SENUELO_API_KEY``.

    Si no hay API key configurada, la API corre abierta (modo dev) y esta
    dependencia no bloquea. La comparación es en tiempo constante.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key or ""):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key inválida o ausente (header X-API-Key)",
        )
