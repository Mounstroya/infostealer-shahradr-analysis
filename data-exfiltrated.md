# Qué datos puede robar este malware

**Importante:** esta investigación llegó hasta desempaquetar el stub cargador del payload final (ver [`analysis/03-payload-analysis.md`](analysis/03-payload-analysis.md)), pero **no se decompilaron las funciones reales de robo de datos** — el mapeador manual de PE quedó incompleto (falta un puntero que se parcha justo antes de la ejecución real). Por lo tanto, lo que sigue es una combinación de:

- **Confirmado por el análisis:** la existencia de un panel C2 diseñado para recibir credenciales/cookies (mencionado explícitamente en el reporte forense inicial, ver [`analysis/04-c2-communication.md`](analysis/04-c2-communication.md)), y el hecho de que el binario referencia librerías CRT estándar de Windows que son consistentes con esta clase de malware.
- **No confirmado / inferido por familia:** el detalle exacto de qué archivos lee, qué APIs de DPAPI/SQLite3 invoca y qué formato de exfiltración usa — porque esas funciones nunca llegaron a ejecutarse ni decompilarse en esta sesión.

## Categorías típicas de un InfoStealer de este tipo (panel C2 "PB-Fire", en ruso)

Esta familia de paneles suele apuntar a las siguientes categorías de datos en el equipo comprometido (**genérico de la familia, no confirmado dato por dato en esta muestra**):

- Contraseñas guardadas en navegadores basados en Chromium/Firefox (protegidas con DPAPI en Windows).
- Cookies de sesión activas (permiten secuestrar sesiones ya logueadas sin necesitar la contraseña).
- Historial y autocompletado de formularios.
- Datos de wallets de criptomonedas (extensiones de navegador o archivos locales de wallets de escritorio), común en esta clase de campañas.
- Archivos de configuración de clientes FTP/VPN/mensajería si el stealer incluye "grabbers" adicionales.
- Capturas de pantalla o información del sistema (fingerprinting), consistente con el chequeo de IP/geolocalización encontrado en el payload parcial (`ipinfo.io/what-is-my-ip`).

## Qué hacer si tu equipo estuvo expuesto a esta muestra

Dado que no se confirmó el alcance exacto, la recomendación de higiene es tratar el incidente como si **todo lo anterior** hubiera sido robado:

1. Rotar contraseñas de todas las cuentas guardadas en el navegador del equipo afectado (idealmente desde otro dispositivo limpio).
2. Cerrar sesión de todos los dispositivos en los servicios críticos (invalida cookies de sesión robadas).
3. Revisar y mover fondos de cualquier wallet de criptomonedas expuesta.
4. Activar 2FA donde no estuviera activo.
5. Reinstalar el sistema operativo del equipo comprometido en vez de solo "limpiar" el malware — un InfoStealer de este nivel de sofisticación (cifrado real, evasión con Thread Pool, anti-sandbox) no es trivial de erradicar con confianza total vía limpieza manual.

## Trabajo pendiente para confirmar el alcance real

Completar la reconstrucción descrita en [`analysis/03-payload-analysis.md`](analysis/03-payload-analysis.md) permitiría decompilar las funciones reales y reemplazar esta sección por hallazgos confirmados en vez de inferencias de familia.
