# Hito 1 · Diseño seguro

Copien esta carpeta a `docs/hito-1/` del repositorio de su aplicación y
completen cada sección. Borren las líneas que empiezan con *Instrucción*.

Integrantes y roles:

| Nombre | Usuario GitHub | Rol |
|---|---|---|
| Fabiola Contreras | [@Fabiola-cc](https://github.com/Fabiola-cc) | Equipo rojo (Red Team) |
| María José Villafuerte | [@Maria-Villafuerte](https://github.com/Maria-Villafuerte) | Equipo rojo (Red Team) |
| Andree Toledo | [@andreetoledo](https://github.com/andreetoledo) | Equipo azul (Blue Team) |
| Sofía Velásquez | [@Sofiamishel2003](https://github.com/Sofiamishel2003) | Equipo azul (Blue Team) |

## DFD

*Instrucción: diagrama de flujo de datos de su aplicación, con los límites de
confianza marcados. Guarden la imagen en esta carpeta, por ejemplo como
`dfd.png`, y péguenla debajo.*

## STRIDE

*Instrucción: una amenaza por letra. El componente es de su app, no un ejemplo
genérico.*

| Letra | Amenaza | Componente | Control |
|---|---|---|---|
| Suplantación |  |  |  |
| Manipulación |  |  |  |
| Repudio |  |  |  |
| Divulgación de información |  |  |  |
| Denegación de servicio |  |  |  |
| Elevación de privilegios |  |  |  |

## PASTA

*Instrucción: etapas 1 a 5. La etapa 5 reutiliza los hallazgos del Proyecto
DAST. Las etapas 6 y 7 se cierran en el Hito 2 y en el informe.*

### Etapa 1 · Objetivos del negocio

### Etapa 2 · Alcance técnico

### Etapa 3 · Descomposición de la aplicación

### Etapa 4 · Análisis de amenazas

### Etapa 5 · Vulnerabilidades

| Hallazgo (del DAST) | Dónde está | Relación con el DFD |
|---|---|---|
|  |  |  |

## Superficie de ataque

*Instrucción: la aporta el Equipo rojo. Rutas y métodos, roles, límites de
confianza (navegador, API, base de datos y el WAF) y los hallazgos del DAST que
van a convertirse en PoC del Hito 2. Si el puerto original de la app responde,
anótenlo aquí como bypass del WAF. Guarden el mapa en esta carpeta, por ejemplo
como `superficie.png`.*

## Requisitos de seguridad

*Instrucción: la columna «Control que lo comprueba» la llena el Equipo azul.
Escriban pipeline, regla de Kibana o WAF, y en la última columna cómo se va a
ver ese control en el Hito 2, 3 o 4.*

| ID | Requisito | Amenaza que cubre | Control que lo comprueba | Cómo se comprueba después |
|---|---|---|---|---|
| RS-01 |  |  |  |  |

## Casos de abuso

*Instrucción: al menos cinco, en formato Dado / Cuando / Entonces.*

### CA-01 ·

- **Dado**
- **Cuando**
- **Entonces**

### CA-02 ·

- **Dado**
- **Cuando**
- **Entonces**

### CA-03 ·

- **Dado**
- **Cuando**
- **Entonces**

### CA-04 ·

- **Dado**
- **Cuando**
- **Entonces**

### CA-05 ·

- **Dado**
- **Cuando**
- **Entonces**
