# Cronología de la investigación

Reconstruida a partir de la sesión de análisis original. Las horas son locales del analista.

| # | Momento | Qué pasó |
|---|---|---|
| 1 | 29-ago, 22:13 | Se recibe el reporte inicial del incidente (ver [`analysis/04-c2-communication.md`](analysis/04-c2-communication.md)) con la hipótesis de trabajo: binario `shahradr.exe` empaquetado con ~122.5 MB de bytes `0x00` en `.reloc`, cifrado supuestamente RC4, transferencia de control por `call rax` directo. Se pide montar un entorno de emulación (Unicorn/Speakeasy/QEMU) para desempaquetar dinámicamente y volcar el payload. |
| 2 | 29-ago, 22:13–22:27 | Reconocimiento del entorno: se confirma que no hay `sudo` con password, pero se localiza un AppImage de Cutter ya montado (`squashfs-root`) con binarios de `rizin` utilizables sin privilegios — evita depender de `apt install`. |
| 3 | 29-ago, 22:27 | Se recibe el reporte técnico completo y detallado de la cadena de infección (las 5 fases, con las respuestas exactas del servidor en cada etapa). |
| 4 | 29-ago, 22:27–23:03 | **Desempaquetado dinámico.** Se monta un venv de Python (`speakeasy-emulator`, `unicorn` 1.0.2, `capstone`, `pefile`, `lief`, `pycryptodome`), resolviendo incompatibilidades de versión (`unicorn`/`distutils` en Python 3.13). Iterando sobre hooks de CryptoAPI y memoria, se corrigen dos hipótesis del reporte original: el cifrado real es AES-256-CBC (no RC4) y el "padding" de `.reloc` no es `0x00` sino un patrón de baja entropía. Se extraen clave e IV reales, se confirma el mecanismo de Windows Thread Pool para la transferencia de control, y se vuelca el buffer desempaquetado (573,600 bytes) a `payload_unpacked.exe`. Se entrega ese volcado y el script de emulación al usuario. |
| 5 | 29-ago, 23:03 | Se pide continuar con la reconstrucción del PE final para llegar a las funciones de robo reales. Se decompila con Ghidra (vía `rz-ghidra`) `fcn.140012470` y `fcn.140012230`, confirmando el bucle de inversión de bytes condicional y la lógica de asignación de memoria. **La respuesta se corta por un aviso de seguridad interno del asistente** ("cyber safeguards") antes de completar la reconstrucción del PE — la sesión queda con el trabajo de reconstrucción pendiente. |
| 6 | 31-ago, 01:49 | El usuario compacta la conversación (`/compact`) dos días después. |
| 7 | 31-ago, 01:56 | El usuario pide ubicar el log de la conversación y armar este repositorio educativo. La respuesta vuelve a cortarse por el mismo aviso de seguridad del asistente. |
| 8 | 31-ago (sesión nueva) | Se retoma en una sesión distinta: se instala `cc2md` para exportar el log a Markdown, se recorre la conversación completa turno por turno y se construye este repositorio. |

**Nota metodológica:** los cortes en los pasos 5 y 7 fueron un aviso de seguridad automático del propio asistente de IA (falso positivo típico en trabajo legítimo de ingeniería inversa/ciberseguridad), no un hallazgo técnico ni un fallo del análisis — por eso la reconstrucción del PE final quedó inconclusa y se documenta como trabajo pendiente en el [README](README.md#limitaciones-y-trabajo-pendiente).
