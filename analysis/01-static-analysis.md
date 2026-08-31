# 01 — Análisis estático

## El archivo

- **Nombre:** `shahradr.exe`
- **Tamaño original:** 126.5 MB (`126525440` bytes)
- **Tipo:** PE32+ para Windows, x86-64, GUI, *stripped* (símbolos externos en PDB)
- **Secciones:** 11
- **Compilador:** GCC MinGW-w64 x86_64
- **Dependencias CRT referenciadas:**
  - `kernel32.dll`
  - `api-ms-win-crt-environment-l1-1-0.dll`
  - `api-ms-win-crt-heap-l1-1-0.dll`
  - `api-ms-win-crt-locale-l1-1-0.dll`
  - `api-ms-win-crt-math-l1-1-0.dll`
  - `api-ms-win-crt-private-l1-1-0.dll`
  - `api-ms-win-crt-runtime-l1-1-0.dll`
  - `api-ms-win-crt-stdio-l1-1-0.dll`
  - `api-ms-win-crt-string-l1-1-0.dll`

## Hallazgo 1 — el "padding" de `.reloc` no son bytes nulos

El reporte inicial del incidente afirmaba que la sección `.reloc` había sido inflada con **122.5 MB de bytes `0x00`** para evadir sandboxes automatizadas (heurística común: "archivo demasiado pesado, se descarta el análisis").

Al muestrear la sección completa en el binario original de 126 MB, se encontró que **casi el 100% de los bytes son distintos de cero**. La hipótesis correcta es que se trata de un **patrón repetitivo de 16 bytes con baja entropía (~3.9 bits/byte)** — sigue siendo relleno de evasión (mismo objetivo: inflar el tamaño del archivo), pero no es la técnica de "padding con ceros" que se asumió inicialmente.

Esto también confirma que truncar el binario a los primeros 5 MB (ver abajo) es seguro: el payload real no está oculto en la cola de baja entropía.

## Recorte del binario (*unpadding*)

```bash
dd if=/tmp/malware_extract/shahradr.exe of=/tmp/shahradr_clean.exe bs=1M count=5
```

Resultado: binario funcional de 5.0 MB, usable directamente en Cutter/rizin sin necesidad de cargar los 126 MB completos.

## Puntos de entrada y direcciones clave

| Dirección / símbolo | Rol |
|---|---|
| `entry0` @ `0x140001420` | Punto de entrada del binario. Wrapper ligero que invoca `fcn.140001020`. |
| `fcn.140001020` | Inicialización del C-Runtime de MinGW-w64. Al terminar, transfiere control a `fcn.140012470`. |
| `fcn.140012470` | Núcleo del desempaquetador. Ver [`02-unpacking.md`](02-unpacking.md) para el detalle de lo que hace en runtime. |
| `0x1400123b0` – `0x14001240f` | Bloque de "junk code" (instrucciones NOP semánticas: `lea rsi,[rsi]`, `xchg rdi,rdi`, `mov r14,r14`) seguido de la transferencia real de control (`call rax` en `0x14001240f`). Diseñado para dificultar el seguimiento en un desensamblador lineal. |

## Herramientas usadas en esta fase

Ver [`../tools-used.md`](../tools-used.md) para el detalle completo. En resumen: Cutter (AppImage) + su `rizin` embebido, ejecutados sin `sudo` extrayendo los binarios del `squashfs-root` montado por el propio AppImage.
