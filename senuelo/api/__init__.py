"""Capa web (FastAPI) de Señuelo.

Envuelve los motores de ``scope`` y ``scoring`` en una API HTTP.
"""

from .app import app, create_app

__all__ = ["app", "create_app"]
