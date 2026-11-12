# Hito 3 · Detección y respuesta

Copien esta carpeta a `docs/hito-3/` del repositorio de su aplicación.
El export de Kibana no va aquí: va en `waf-siem/kibana-export.ndjson`.

Cómo está conectada la app al WAF (opción A o B) y qué riesgo aceptan si el
puerto original sigue expuesto:

## Reglas

*Instrucción: al menos tres, guardadas en Discover. Cada una tiene que
detectar un ataque real del Equipo rojo. Peguen la captura (hora y payload
visibles) en esta carpeta.*

| Regla | KQL | Ataque que detecta | Captura |
|---|---|---|---|
| DET-01 | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 942*` |  |  |
| DET-02 | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 941*` |  |  |
| DET-03 | `fields.fuente : "waf-audit" and modsec.transaction.messages.details.ruleId : 911100` |  |  |

El KQL de la tabla es el de partida. Cámbienlo si su ataque dispara otra regla,
y dejen la consulta que sí encontró el evento.

## Dashboard

- Nombre: `WAF - Blue Team`
- Paneles (eventos en el tiempo, top de reglas, top de rutas, top de IP):
- Captura:

## Exclusiones

*Instrucción: el WAF ya está en `MODSEC_RULE_ENGINE=On`. Cada fila es un falso
positivo encontrado usando la app como usuario normal. La exclusión más pequeña
posible; no se apaga el CRS. Los tipos y qué investigar si el ejemplo no
aplica están en la guía del Equipo azul, sección Exclusiones.*

| Regla | Ruta o parámetro | Qué se excluyó | Por qué es legítimo | Archivo |
|---|---|---|---|---|
|  |  |  |  | `waf-siem/waf/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` |

## Demo Purple Team

- PoC que se repite en vivo:
- Hora acordada:
- Qué muestra el Equipo azul (detección y bloqueo):
