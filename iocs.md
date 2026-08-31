# Indicadores de Compromiso (IOCs)

Todos estos indicadores son del **atacante/infraestructura maliciosa**, no del sistema de la víctima — se mantienen sin redactar porque son justamente lo que sirve para detectar/bloquear esta campaña.

## Dominios y URLs

| Indicador | Rol |
|---|---|
| `dragonphoenixstar.cfd` | Stage 1 — sirve `/file.php`, el primer script PowerShell |
| `sillygoosetoon.cfd` | Stage 2 — sirve `/get.php` y `/download/archive.7z` |
| `http://91.92.33.156/panel/pb-fire` | Panel C2 (interfaz en ruso), endpoint de exfiltración |

## Red

| Indicador | Valor |
|---|---|
| IP del C2 | `91.92.33.156` |
| User-Agent usado por el loader | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36` |
| Petición anti-sandbox encontrada en el payload | `GET /what-is-my-ip HTTP/1.1` a `ipinfo.io` |

## Artefactos y contraseñas

| Indicador | Valor |
|---|---|
| Nombre del binario | `shahradr.exe` |
| Contraseña del contenedor `.7z` | `ShahradR_Pass2026` |
| Marcador de infección | archivo `*.ok` en `%APPDATA%` / `%LOCALAPPDATA%` |
| Tamaño binario original (con padding) | 126,525,440 bytes (126.5 MB) |
| Tamaño binario recortado (sin padding, funcional) | 5,242,880 bytes (5 MB) |
| Tamaño del payload descifrado | 573,600 bytes (`0x8c0a0`) |

## Criptografía interna (para replicar el desempaquetado)

| Indicador | Valor |
|---|---|
| Algoritmo | AES-256-CBC (Windows CryptoAPI, `CALG_AES_256`) |
| Clave (32 bytes, hex) | `cfcc13c0242c3d3cabaf192aee60adb06b3246547ab35444b0a5ee2ade97821` |
| IV (16 bytes, hex) | `ea2f9b0cf0859c950c2cc2574780e05` |

## Direcciones internas del binario (build específico analizado)

| Dirección | Rol |
|---|---|
| `0x140001420` | `entry0` |
| `0x140001020` | Init del CRT (MinGW-w64) |
| `0x140012470` | Núcleo del desempaquetador |
| `0x140012230` | Función de asignación de memoria / inversión de bytes condicional |
| `0x1400123b0` – `0x14001240f` | Junk code + transferencia real de control |

> Estas direcciones son válidas para esta build específica del malware (offsets internos del binario) — útiles para YARA/scripts de desempaquetado dirigidos a esta muestra, pero es esperable que cambien en variantes/recompilaciones futuras de la misma familia.
