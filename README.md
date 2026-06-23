# Señuelo

Plataforma de **simulación de phishing para concientización**, diseñada en torno
a una tesis incómoda: la investigación reciente muestra que la mayoría de estas
simulaciones, tal como se hacen hoy, casi no cambian el comportamiento y a veces
**erosionan la confianza** (la gente reporta menos las amenazas reales por miedo
al castigo). Señuelo está construido para corregir exactamente eso.

> Un señuelo que **entrena** en vez de cazar. El ejercicio solo existe con
> consentimiento, dentro de un alcance autorizado y con feedback que suma.

## Qué lo diferencia de un clon de GoPhish

1. **Consentimiento y autorización como núcleo.** Nada se envía sin una
   autorización firmada y vigente. El alcance es duro: un destinatario fuera de
   los dominios autorizados se rechaza, no se "asume autorizado".
2. **Métrica basada en evidencia.** El KPI primario es la **tasa de reporte**
   (resiliencia), no la tasa de click (susceptibilidad), normalizada por
   dificultad con el **NIST Phish Scale**.
3. **Feedback no punitivo y diferido.** Se entrena a toda la cohorte tras la
   campaña, no solo a quien cae, evitando los patrones que la investigación
   marca como contraproducentes.
4. **Minimización de datos por diseño.** Se registra el *evento* ("envió datos"),
   nunca la credencial; con retención acotada, en línea con la Ley 19.628.

## Estado

| Módulo | Estado |
|---|---|
| `scope` — motor de alcance y autorización | ✅ implementado |
| `scoring` — NIST Phish Scale (dificultad + contexto de click rate) | ✅ implementado |
| `api` — capa FastAPI (autorizaciones + scoring, API key) | ✅ implementado |
| `storage` — persistencia SQLite + audit log inmutable (cadena de hashes) | ✅ implementado |
| `campaigns` — ciclo de vida + tracking simulado (dry-run) | ✅ implementado |
| `delivery` (envío real, con cautela), `training` (no-embedded), `dashboard` | 🔜 |

## El motor de alcance (`senuelo.scope`)

Es el guardia de la plataforma. Una `Authorization` traduce las *rules of
engagement* a datos verificables y firmados; el `ScopeEngine` decide, con
motivo auditable, quién puede ser objetivo.

```python
from datetime import datetime, timedelta, timezone
from senuelo.scope import Authorization, Party, ScopeEngine, sign

now = datetime.now(timezone.utc)
auth = Authorization(
    organization="Empresa Demo SpA",
    authorized_by=Party(name="Ana Soto", role="CISO", email="ana.soto@empresa.cl"),
    requested_by=Party(name="Red Team", role="Operador", email="rt@consultora.cl"),
    scope_domains=["empresa.cl"],
    excluded_addresses=["gerencia.general@empresa.cl"],
    window_start=now - timedelta(days=1),
    window_end=now + timedelta(days=14),
    data_retention_days=90,
    consent_reference="Anexo RoE 2026-04",
)
sign(auth, key="...")  # o variable de entorno SENUELO_SIGNING_KEY

report = ScopeEngine(auth, key="...").filter_recipients([
    "juan.perez@empresa.cl",        # admitido
    "contratista@gmail.com",        # fuera de alcance
    "gerencia.general@empresa.cl",  # excluido (opt-out)
])
print(report.admitted, report.rejected)
```

Salida del `examples/quickstart.py`:

```
Autorización 7ea388dc — estado: active
Alcance: empresa.cl | retención: 90 días

Admitidos (2):
  ✓ juan.perez@empresa.cl
  ✓ maria.lopez@empresa.cl

Rechazados (4):
  ✗ gerencia.general@empresa.cl   [excluded_recipient] destinatario en lista de exclusión
  ✗ contratista@gmail.com         [out_of_scope] dominio fuera del alcance autorizado: gmail.com
  ✗ user@correo.empresa.cl        [out_of_scope] dominio fuera del alcance autorizado: correo.empresa.cl
  ✗ direccion-mala                [malformed_recipient] dirección de correo inválida
```

### Garantías de diseño

- **Antimanipulación.** La autorización se sella con HMAC-SHA256 sobre un payload
  canónico. Editar el alcance, la ventana o las exclusiones después de firmar
  invalida la firma: el motor rechaza la campaña entera.
- **Falla-cerrado.** Firma inválida, autorización sin firmar, fuera de ventana,
  revocada o destinatario malformado ⇒ denegación explícita y tipada.
- **Toda decisión es auditable.** Cada rechazo lleva un código estable y un
  motivo legible, pensados para alimentar el audit log inmutable.

## El scoring de dificultad (`senuelo.scoring`)

Implementación fiel del **NIST Phish Scale** (Steves, Greene & Theofanos, 2020).
Puntúa la dificultad de detección de una plantilla combinando dos dimensiones:

- **Señales (cues):** catálogo de 23 características observables en 5 categorías
  (errores, indicadores técnicos, presentación visual, lenguaje/contenido,
  tácticas comunes). Más señales ⇒ más fácil de detectar. El conteo se clasifica
  en `Few` (1–8), `Some` (9–14) o `Many` (15+).
- **Alineación de premisa:** qué tan bien calza el pretexto con el contexto de
  la audiencia. Por Método 1 (directo `Low`/`Medium`/`High`) o Método 2
  (formulaico: 5 elementos en escala 0–8, sumando 1–4 y restando el de
  entrenamiento previo; `Low` ≤10, `Medium` 11–17, `High` ≥18).

La Tabla 1 del paper combina ambas en una dificultad de detección, y cada
dificultad trae su **rango esperado de click rate**. Eso permite *contextualizar*
las métricas:

```python
from senuelo.scoring import (
    PhishScaleAssessment, PremiseAlignment, contextualize_click_rate,
)

a = PhishScaleAssessment.from_cue_list(
    ["mimics_business_process", "url_hyperlinking"],   # 2 señales -> Few
    target_audience="Finanzas (paga facturas)",
    premise_alignment=PremiseAlignment.HIGH,
)
r = a.result()
print(r.detection_difficulty.label_es)            # "Muy difícil"
print(contextualize_click_rate(r, 22.0).message)  # 22% está dentro de lo esperado...
```

Salida de `examples/scoring_quickstart.py`:

```
== Factura impaga a Finanzas (dirigido) ==
  Señales: 2 (few) | premisa: high (Método 1)
  Dificultad: Muy difícil (esperado 19–100% de click)
  Observado: 22.0% está dentro de lo esperado (19–100%) para un phish 'Muy difícil'.

== Lotería sospechosa (genérico) ==
  Señales: 15 (many) | premisa: 4 (low)
  Dificultad: Poco difícil (esperado 0–10% de click)
  Observado: 24.0% supera el rango esperado (0–10%): vale la pena investigar.
```

Ese es el argumento del Phish Scale en acción: el mismo click rate significa
cosas opuestas según la dificultad. Sin normalizar por dificultad, comparar
campañas es engañarse.

## La capa web (`senuelo.api`)

API FastAPI que envuelve los motores de `scope` y `scoring`. Decisiones de
seguridad: la clave de firmado y la API key se leen del **entorno del servidor**
(`SENUELO_SIGNING_KEY`, `SENUELO_API_KEY`), nunca del cliente ni del código; si
hay API key configurada, se exige el header `X-API-Key` (comparación en tiempo
constante); el repositorio de autorizaciones está tras una interfaz para migrar
a base de datos sin tocar los endpoints.

Levantar en desarrollo:

```bash
export SENUELO_SIGNING_KEY="una-clave-larga-y-secreta"
uvicorn senuelo.api.app:app --reload
# documentación interactiva en http://127.0.0.1:8000/docs
```

Endpoints principales:

| Método | Ruta | Qué hace |
|---|---|---|
| `GET` | `/health` | Estado y flags de configuración |
| `POST` | `/authorizations` | Crea y **firma** una autorización |
| `GET` | `/authorizations/{id}` | Consulta una autorización |
| `POST` | `/authorizations/{id}/revoke` | Revoca (re-firma el cambio) |
| `POST` | `/authorizations/{id}/recipient-check` | Valida destinatarios contra el alcance |
| `GET` | `/scoring/cues` | Catálogo de las 23 señales |
| `POST` | `/scoring/assess` | Dificultad de una plantilla |
| `POST` | `/scoring/contextualize` | Interpreta un click rate observado |

Ejemplo: validar destinatarios contra una autorización devuelve quién entra y
por qué se rechaza cada quien:

```json
{
  "admitted": ["ok@empresa.cl"],
  "rejected": [
    {"email": "fuera@gmail.com", "code": "out_of_scope", "reason": "dominio fuera del alcance autorizado: gmail.com"},
    {"email": "jefe@empresa.cl", "code": "excluded_recipient", "reason": "destinatario en lista de exclusión: jefe@empresa.cl"}
  ],
  "admitted_count": 1, "rejected_count": 2, "total": 3
}
```

## Persistencia y audit log inmutable (`senuelo.storage`)

Sin configuración, la API guarda en memoria (cómodo para dev/tests). Si se
define `SENUELO_DB_PATH`, las autorizaciones y la bitácora pasan a **SQLite** y
sobreviven a los reinicios:

```bash
export SENUELO_SIGNING_KEY="clave-secreta"
export SENUELO_DB_PATH="./senuelo.db"
uvicorn senuelo.api.app:app
```

El repositorio SQLite implementa la misma interfaz que el de memoria, así que la
API no distingue cuál usa (migrar a Postgres es agregar otra implementación).

El **audit log es inmutable en dos capas**: cada entrada encadena el hash de la
anterior (alterar una entrada pasada rompe la cadena y `verify` lo detecta), y
en SQLite dos triggers abortan cualquier `UPDATE` o `DELETE` sobre la tabla.
Endpoints: `GET /audit` lista la bitácora, `GET /audit/verify` comprueba la
integridad de la cadena.

Demostración de durabilidad (crear+revocar, reiniciar el servidor, reconsultar):

```
# tras reiniciar con la misma DB:
GET /authorizations/{id}     -> status: revoked, firma intacta
GET /audit/verify            -> {"valid": true, "entries": 2,
                                 "message": "la cadena de auditoría es íntegra"}
```

## Campañas (`senuelo.campaigns`)

El módulo que une todo. Una campaña referencia una **autorización**, embebe una
**plantilla evaluada** con el Phish Scale y lleva una **lista de destinatarios**.
Su ciclo de vida es una máquina de estados estricta:

```
draft ──schedule──▶ scheduled ──launch──▶ running ──complete──▶ completed
  └──────────────── cancel ────────────────▶ cancelled
```

Al **lanzar** (en modo dry-run, sin enviar correos), la campaña valida los
destinatarios contra el alcance (motor de scope) y genera **eventos de tracking
simulados** cuyo embudo se modela a partir de la dificultad de la plantilla
(NIST Phish Scale). De ahí emerge la métrica que distingue al proyecto: la
**tasa de reporte**. Cada transición queda en el audit log inmutable.

Decisión ética heredada: el evento `submitted` registra que la persona envió
datos, **nunca qué datos**.

Endpoints: `POST /campaigns`, `/schedule`, `/launch`, `/complete`, `/cancel`,
más `GET /campaigns/{id}/events` y `/metrics`.

Salida de `examples/campaign_quickstart.py`:

```
Campaña: Factura impaga a Finanzas  [running]
Dificultad de la plantilla: Muy difícil

Destinatarios: 30 admitidos, 2 rechazados
  ✗ fuera@gmail.com [out_of_scope]
  ✗ jefe@empresa.cl [excluded_recipient]

Embudo (dry-run):
  Enviados:  30
  Abiertos:  21  (70.0%)
  Clicks:    10  (33.3%)
  Enviaron datos: 6  (20.0%)
  REPORTARON: 3  (10.0%)   <- KPI de resiliencia
```

## Desarrollo

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # 81 tests
PYTHONPATH=. python examples/quickstart.py
PYTHONPATH=. python examples/scoring_quickstart.py
PYTHONPATH=. python examples/campaign_quickstart.py
export SENUELO_SIGNING_KEY="clave-secreta" && uvicorn senuelo.api.app:app --reload
```

## Uso responsable

Señuelo está pensado **exclusivamente para ejercicios autorizados** de
concientización. El motor de alcance no es una formalidad: es la barrera que
impide convertir la herramienta en un instrumento de ataque. Ejecutar campañas
de phishing contra personas sin autorización explícita puede ser ilegal y es
éticamente inaceptable.
