# Herramientas usadas en la investigación

| Herramienta | Versión | Para qué se usó |
|---|---|---|
| **Claude Code** | v2.1.246 | Agente de IA que condujo la investigación completa de forma interactiva: reconocimiento del entorno, instalación y depuración del entorno de emulación, escritura del script de desempaquetado, uso de rizin/Ghidra, y síntesis de hallazgos. |
| **Debian GNU/Linux** | — | Sistema anfitrión del análisis. Sin acceso `sudo` con password durante toda la sesión — todo el trabajo se hizo en espacio de usuario. |
| **`dd`** | — | Recorte (*unpadding*) del binario de 126.5 MB a 5 MB (`bs=1M count=5`), eliminando el relleno de baja entropía sin perder el código real. |
| **Cutter** (AppImage) | — | GUI de ingeniería inversa. Se aprovechó su AppImage ya montado (`squashfs-root`) para reutilizar sus binarios internos de `rizin` sin instalar nada vía `apt`. |
| **rizin** | 0.7.1 (extraído del AppImage de Cutter) | Desensamblado estático headless (`rz-asm`), listado de funciones, y motor de análisis para el plugin de Ghidra. |
| **rz-ghidra** (`core_ghidra.so`) | integrado en Cutter | Decompilador de Ghidra vía rizin, usado para obtener pseudocódigo C de `fcn.140012470` y `fcn.140012230`. Requirió apuntar `SLEIGHHOME` a las especificaciones Sleigh (`x86-64.sla`) incluidas en el propio AppImage. |
| **Python** | 3.13.5 | Lenguaje del entorno de emulación. |
| **venv de Python aislado** | — | Entorno virtual dedicado (`malware_venv`), sin tocar el Python del sistema. |
| **Speakeasy** (`speakeasy-emulator`) | 1.5.11 | Motor de emulación de Windows PE (sobre Unicorn) usado para ejecutar el stub desempaquetador del binario sin un sistema Windows real, con hooks personalizados sobre CryptoAPI, memoria y Thread Pool APIs. |
| **Unicorn Engine** | 1.0.2 (fijado a propósito) | Motor de emulación de CPU subyacente de Speakeasy. Se mantuvo en 1.0.2 (en vez de 2.x) porque Speakeasy 1.5.11 no es compatible con la API interna de Unicorn 2.x. |
| **setuptools** | — | Proveía el shim de compatibilidad para `distutils`, eliminado en Python 3.13 pero requerido por `unicorn==1.0.2`. |
| **Capstone** | 5.0.9 | Motor de desensamblado usado internamente por el tooling de análisis. |
| **pefile** / **lief** | 2024.8.26 / 1.0.0 | Parseo de estructuras PE (cabeceras, secciones) desde Python. |
| **pycryptodome** | — | Verificación independiente del descifrado AES-256-CBC (confirmar clave/IV reales fuera del propio emulador). |
| **`strings`** | — | Extracción de cadenas ASCII/UTF-16LE del buffer desempaquetado para encontrar indicios legibles (la petición HTTP a `ipinfo.io`). |

## Script propio de análisis

Durante la investigación se escribió (y se fue corrigiendo iterativamente) un script de Python, `unpack_shahradr.py`, que:

1. Carga `shahradr_clean.exe` en Speakeasy con su base e imagen originales.
2. Registra hooks sobre las APIs de CryptoAPI (`CryptAcquireContextW`, `CryptImportKey`, `CryptSetKeyParam`, `CryptDecrypt`) para loguear y, cuando hizo falta, reimplementar el descifrado real (parseando el `BLOBHEADER` de la clave).
3. Registra un hook sobre `CreateThreadpoolWork` para capturar el puntero de contexto (el buffer ya descifrado) en el momento exacto en que se programa el callback, sin necesitar re-ejecutar la función real y lidiar con problemas de reentrancia del emulador.
4. Vuelca a disco los buffers relevantes para su análisis posterior con `strings`/rizin.

Este repositorio **no incluye el script ni los binarios/volcados generados** (por decisión explícita de no subir archivos ejecutables ni muestras) — solo esta descripción de su funcionamiento, suficiente para que alguien con el mismo binario pueda reproducir el proceso.
