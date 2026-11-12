# Informe final · Proyecto Final Integrador

Copien este archivo, completen las secciones y entreguen el PDF en Canvas con
el enlace al repositorio. Los pesos y la rúbrica están en el enunciado.

Grupo:

| Nombre | Usuario GitHub | Rol |
|---|---|---|
| Fabiola Contreras | [@Fabiola-cc](https://github.com/Fabiola-cc) | Equipo rojo (Red Team) |
| María José Villafuerte | [@Maria-Villafuerte](https://github.com/Maria-Villafuerte) | Equipo rojo (Red Team) |
| Andree Toledo | [@andreetoledo](https://github.com/andreetoledo) | Equipo azul (Blue Team) |
| Sofía Velásquez | [@Sofiamishel2003](https://github.com/Sofiamishel2003) | Equipo azul (Blue Team) |

Repositorio: https://github.com/andreetoledo-org/secure-crm-proyecto-final

## Matriz de trazabilidad

*Una fila por vulnerabilidad. Es el eje del informe: quién la encontró, qué la
detectó, qué la bloqueó y cómo se corrigió.*

| Hallazgo | OWASP / CWE | CVSS v3.1 | ¿Pipeline? | ¿SIEM? | ¿WAF? | Corrección | Re-prueba |
|---|---|---|---|---|---|---|---|
|  |  |  |  |  |  |  |  |

- **¿Pipeline?** Qué control lo vio (SAST, SCA, DAST) o por qué no.
- **¿SIEM?** Regla de Kibana (`DET-*`) y la hora del evento.
- **¿WAF?** Regla del CRS y si, en modo On, la petición termina en 403.
- **Re-prueba.** El mismo PoC con el WAF en DetectionOnly, después de corregir
  el código.

## Línea de tiempo del ataque

*Salga del registro de `docs/hito-2/`. Hora y payload en cada fila.*

| Hora | Quién | Qué pasó | Payload |
|---|---|---|---|
|  |  |  |  |

## Exclusiones del WAF

*Las de `docs/hito-3/`, con la justificación al lado. Una exclusión sin
justificación no cuenta.*

| Regla | Qué se excluyó | Por qué el tráfico es legítimo |
|---|---|---|
|  |  |  |

## Riesgo residual (PASTA, etapa 7)

Qué quedó sin corregir, qué cubre solo el WAF (y se cae si alguien llega
directo a la app) y qué riesgo acepta el grupo.

## Lecciones aprendidas

Qué cambió en la forma de diseñar, detectar y corregir. Concretas: una
herramienta, un falso positivo, un hallazgo que el pipeline no vio.
