"""App FastAPI de Señuelo.

Arranque en desarrollo:
    uvicorn senuelo.api.app:app --reload

Documentación interactiva en /docs una vez levantado.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, RedirectResponse

from .. import __version__
from .config import get_settings
from .routers import audit, authorizations, campaigns, dashboard, scoring

_STATIC = Path(__file__).parent / "static"

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

    @app.get("/dashboard", include_in_schema=False)
    def dashboard_page() -> FileResponse:
        return FileResponse(_STATIC / "dashboard.html")

    app.include_router(authorizations.router)
    app.include_router(campaigns.router)
    app.include_router(scoring.router)
    app.include_router(audit.router)
    app.include_router(dashboard.router)

    settings = get_settings()
    if settings.seed_demo and settings.signing_enabled:
        from .campaign_repository import get_campaign_repository
        from .repository import get_audit_log, get_repository
        from .seed import seed_demo

        seed_demo(get_repository(), get_campaign_repository(),
                  get_audit_log(), settings.signing_key)

    return app


app = create_app()
