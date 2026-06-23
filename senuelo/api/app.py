"""App FastAPI de Señuelo.

Arranque en desarrollo:
    uvicorn senuelo.api.app:app --reload

Documentación interactiva en /docs una vez levantado.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .. import __version__
from .config import get_settings
from .routers import audit, authorizations, scoring

DESCRIPTION = """\
API de **Señuelo**, plataforma de simulación de phishing para concientización.

Diseñada en torno a tres principios: consentimiento y autorización como núcleo,
métricas basadas en evidencia (NIST Phish Scale) y feedback no punitivo.

**Uso responsable.** Esta API está pensada exclusivamente para ejercicios
autorizados. El motor de alcance impide enviar fuera de los dominios y la
ventana temporal autorizados. Ejecutar campañas de phishing contra personas sin
autorización explícita puede ser ilegal y es éticamente inaceptable.
"""


def create_app() -> FastAPI:
    app = FastAPI(
        title="Señuelo API",
        version=__version__,
        description=DESCRIPTION,
    )

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    @app.get("/health", tags=["sistema"])
    def health() -> dict:
        settings = get_settings()
        return {
            "status": "ok",
            "version": __version__,
            "signing_enabled": settings.signing_enabled,
            "auth_enabled": settings.auth_enabled,
            "persistence_enabled": settings.persistence_enabled,
        }

    app.include_router(authorizations.router)
    app.include_router(scoring.router)
    app.include_router(audit.router)
    return app


app = create_app()
