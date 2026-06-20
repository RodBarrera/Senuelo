"""Firmado antimanipulación de autorizaciones.

Se canonicaliza el payload firmable a JSON determinista (claves ordenadas, sin
espacios variables, UTF-8) y se sella con HMAC-SHA256. Verificar consiste en
recomputar el sello y compararlo en tiempo constante.

Por qué HMAC y no solo un hash: el sello depende de una *clave secreta del
servidor*, de modo que nadie puede recalcular una firma válida tras editar el
alcance sin conocer la clave. En una evolución a producción podría sustituirse
por firma asimétrica (la llave del propio autorizante); la interfaz no cambia.

La clave se toma de la variable de entorno ``SENUELO_SIGNING_KEY`` o se pasa
explícitamente (útil en tests). Nunca se hardcodea.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os

from .errors import InvalidSignatureError
from .models import Authorization

_ENV_KEY = "SENUELO_SIGNING_KEY"


def _resolve_key(key: str | bytes | None) -> bytes:
    if key is None:
        key = os.environ.get(_ENV_KEY)
    if not key:
        raise ValueError(
            "falta la clave de firmado: pásala explícitamente o define "
            f"la variable de entorno {_ENV_KEY}"
        )
    return key.encode("utf-8") if isinstance(key, str) else key


def _canonical_bytes(payload: dict) -> bytes:
    """Serializa el payload de forma determinista y reproducible."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def compute_signature(auth: Authorization, key: str | bytes | None = None) -> str:
    """Calcula la firma HMAC-SHA256 del payload canónico de ``auth``."""
    secret = _resolve_key(key)
    digest = hmac.new(secret, _canonical_bytes(auth.canonical_payload()),
                      hashlib.sha256)
    return digest.hexdigest()


def sign(auth: Authorization, key: str | bytes | None = None) -> Authorization:
    """Firma la autorización in situ: fija ``signature`` (y ``signed_at`` si falta).

    Devuelve la misma instancia para encadenar. Firmar de nuevo recalcula el
    sello sobre el estado actual.
    """
    from datetime import datetime, timezone

    # Fijar signed_at ANTES de firmar: así queda dentro del payload sellado y la
    # verificación es reproducible (si se computara después, el payload de verify
    # diferiría del de sign y la firma no validaría).
    if auth.signed_at is None:
        auth.signed_at = datetime.now(timezone.utc)
    auth.signature = compute_signature(auth, key)
    return auth


def verify(auth: Authorization, key: str | bytes | None = None) -> None:
    """Verifica la firma. Lanza :class:`InvalidSignatureError` si no valida.

    Falla-cerrado: una autorización sin firmar también se considera inválida.
    """
    if auth.signature is None:
        raise InvalidSignatureError("la autorización no está firmada")
    expected = compute_signature(auth, key)
    if not hmac.compare_digest(expected, auth.signature):
        raise InvalidSignatureError(
            "la firma no valida: la autorización fue alterada o usa otra clave"
        )
