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
| `campaigns`, `delivery`, `tracking` | 🔜 |
| `scoring` (Phish Scale + human risk) | 🔜 |
| `training` (no-embedded), `dashboard` | 🔜 |
| API FastAPI + `audit` log inmutable | 🔜 |

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

## Desarrollo

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q          # 26 tests
PYTHONPATH=. python examples/quickstart.py
```

## Uso responsable

Señuelo está pensado **exclusivamente para ejercicios autorizados** de
concientización. El motor de alcance no es una formalidad: es la barrera que
impide convertir la herramienta en un instrumento de ataque. Ejecutar campañas
de phishing contra personas sin autorización explícita puede ser ilegal y es
éticamente inaceptable.
