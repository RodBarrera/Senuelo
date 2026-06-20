"""Catálogo de señales (cues) del NIST Phish Scale.

Reproduce, en estructura propia, la Tabla 2 de Steves, Greene & Theofanos
(2020), "Categorizing human phishing difficulty: a Phish Scale". Cada señal es
una característica *objetivamente observable* en un correo; el evaluador cuenta
cuántas instancias hay y suma para obtener el total.

Principio del Phish Scale: menos señales ⇒ más difícil de detectar (menos
oportunidades de sospechar). Por eso el conteo alimenta directamente la
dificultad.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CueCategory(str, Enum):
    """Las cinco categorías de señales, ordenadas de más delatoras a más seductoras."""

    ERROR = "error"
    TECHNICAL = "technical_indicator"
    VISUAL = "visual_presentation"
    LANGUAGE = "language_and_content"
    TACTIC = "common_tactic"


@dataclass(frozen=True)
class Cue:
    """Una señal observable del Phish Scale."""

    id: str
    category: CueCategory
    name: str
    criterion: str  # pregunta-guía para decidir si la señal está presente


CUE_CATALOG: tuple[Cue, ...] = (
    # --- Errores ---------------------------------------------------------
    Cue("spelling_grammar", CueCategory.ERROR,
        "Errores de ortografía y gramática",
        "¿El mensaje tiene errores de ortografía o gramática, o concordancias mal hechas?"),
    Cue("inconsistency", CueCategory.ERROR,
        "Inconsistencias en el contenido",
        "¿Hay contradicciones o inconsistencias dentro del propio mensaje?"),

    # --- Indicadores técnicos -------------------------------------------
    Cue("attachment_type", CueCategory.TECHNICAL,
        "Tipo de adjunto",
        "¿Incluye un adjunto potencialmente peligroso (por ejemplo, ejecutable)?"),
    Cue("sender_display_mismatch", CueCategory.TECHNICAL,
        "Nombre visible vs. dirección real",
        "¿El nombre visible del remitente oculta la dirección real de envío/respuesta?"),
    Cue("url_hyperlinking", CueCategory.TECHNICAL,
        "Hipervínculo que oculta la URL",
        "¿Hay texto enlazado que esconde la URL real de destino?"),
    Cue("domain_spoofing", CueCategory.TECHNICAL,
        "Dominio similar al legítimo",
        "¿Algún dominio en direcciones o enlaces imita a uno legítimo (parecido plausible)?"),

    # --- Presentación visual --------------------------------------------
    Cue("no_minimal_branding", CueCategory.VISUAL,
        "Marca o logos ausentes/mínimos",
        "¿Falta la marca o los logos que cabría esperar?"),
    Cue("logo_imitation_outdated", CueCategory.VISUAL,
        "Logo imitado o desactualizado",
        "¿Algún elemento de marca parece imitación o está desactualizado?"),
    Cue("unprofessional_design", CueCategory.VISUAL,
        "Diseño o formato poco profesional",
        "¿El diseño/formato rompe convenciones de una pieza profesional?"),
    Cue("security_indicators_icons", CueCategory.VISUAL,
        "Indicadores o íconos de seguridad",
        "¿Aparecen indicadores o íconos de seguridad usados de forma inapropiada?"),

    # --- Lenguaje y contenido -------------------------------------------
    Cue("legal_language", CueCategory.LANGUAGE,
        "Lenguaje legal/copyright/avisos",
        "¿Incluye lenguaje legal como copyright, descargos o implicancias tributarias?"),
    Cue("distracting_detail", CueCategory.LANGUAGE,
        "Detalle que distrae",
        "¿Hay detalles accesorios que no son centrales al contenido?"),
    Cue("requests_sensitive_info", CueCategory.LANGUAGE,
        "Solicitud de información sensible",
        "¿Pide información sensible (datos identificatorios, credenciales)?"),
    Cue("sense_of_urgency", CueCategory.LANGUAGE,
        "Sentido de urgencia",
        "¿Usa presión de tiempo, aunque sea implícita, para que actúes rápido?"),
    Cue("threatening_language", CueCategory.LANGUAGE,
        "Lenguaje amenazante",
        "¿Contiene una amenaza, aunque sea implícita (por ejemplo, consecuencias legales)?"),
    Cue("generic_greeting", CueCategory.LANGUAGE,
        "Saludo genérico",
        "¿Carece de saludo o de personalización dirigida al destinatario?"),
    Cue("lack_signer_details", CueCategory.LANGUAGE,
        "Faltan datos del remitente",
        "¿Faltan detalles del firmante, como información de contacto?"),

    # --- Tácticas comunes -----------------------------------------------
    Cue("humanitarian_appeals", CueCategory.TACTIC,
        "Apelación humanitaria",
        "¿Apela a ayudar a otros en necesidad?"),
    Cue("too_good_to_be_true", CueCategory.TACTIC,
        "Oferta demasiado buena",
        "¿Ofrece algo demasiado bueno para ser cierto (premio, lotería, viaje gratis)?"),
    Cue("youre_special", CueCategory.TACTIC,
        "\"Es solo para ti\"",
        "¿Ofrece algo exclusivo y personal para el destinatario?"),
    Cue("limited_time_offer", CueCategory.TACTIC,
        "Oferta por tiempo limitado",
        "¿Ofrece algo por tiempo limitado?"),
    Cue("mimics_business_process", CueCategory.TACTIC,
        "Imita un proceso de trabajo legítimo",
        "¿Aparenta ser un proceso laboral plausible (correo de voz, paquete, factura)?"),
    Cue("poses_as_authority", CueCategory.TACTIC,
        "Se hace pasar por una autoridad/conocido",
        "¿Aparenta venir de un colega, jefe, amigo u otra autoridad?"),
)

CUES_BY_ID: dict[str, Cue] = {cue.id: cue for cue in CUE_CATALOG}


def get_cue(cue_id: str) -> Cue:
    """Devuelve la señal por id, o lanza ``KeyError`` si no existe en el catálogo."""
    try:
        return CUES_BY_ID[cue_id]
    except KeyError as exc:
        raise KeyError(f"señal desconocida: {cue_id!r}") from exc
