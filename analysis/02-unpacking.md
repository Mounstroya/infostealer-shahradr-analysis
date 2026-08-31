# 02 — Desempaquetado dinámico (emulación)

El análisis estático por sí solo no alcanza para desempaquetar el payload: el binario descifra su carga real en memoria en tiempo de ejecución. Se montó un entorno de emulación en Python para ejecutar el stub desempaquetador sin correr el malware en una máquina real.

## Entorno

- Python 3.13 + venv aislado (`speakeasy-emulator`, `unicorn` 1.0.2, `capstone`, `pefile`, `lief`, `pycryptodome`).
- Emulación con **Speakeasy** (sobre el motor **Unicorn**) del binario `shahradr_clean.exe`, cargado con su base e imagen originales (`base=0x140000000`, entry point `0x1420`).
- Sin `sudo` ni acceso privilegiado en ningún momento.

Detalle de la instalación y los problemas de compatibilidad resueltos: [`../tools-used.md`](../tools-used.md).

## Hallazgo 2 — el cifrado real es AES-256-CBC, no RC4

El reporte inicial planteaba un "stream cipher / RC4 con rotación de claves". Instrumentando las llamadas a la CryptoAPI de Windows dentro del emulador se confirmó que el binario usa el **API criptográfico nativo de Windows** con AES real:

```
CryptAcquireContextW(PROV_RSA_AES)
CryptImportKey(bType=8, alg=CALG_AES_256, keylen=32)
CryptSetKeyParam(KP_IV, ...)
CryptDecrypt(...)
```

Datos extraídos directamente de memoria durante la emulación:

- **Clave AES-256 (32 bytes):** `cfcc13c0242c3d3cabaf192aee60adb06b3246547ab35444b0a5ee2ade97821`
- **IV (16 bytes):** `ea2f9b0cf0859c950c2cc2574780e05`

**Verificación matemática de que la clave/IV son correctos:** al desencriptar el primer bloque de ciphertext con esa clave/IV, el resultado coincide exactamente con el IV (propiedad de AES-CBC cuando el primer bloque de plaintext es todo ceros). La probabilidad de que esa coincidencia ocurra por azar es de ~1/2¹²⁸, así que no es casualidad: la clave, el IV y el algoritmo identificados son correctos.

## Flujo de desempaquetado observado

```mermaid
sequenceDiagram
    participant CRT as fcn.140001020 (CRT init)
    participant Core as fcn.140012470 (unpacker)
    participant Buf1 as Buffer RW (0x8c0f0 bytes)
    participant CAPI as CryptoAPI (AES-256-CBC)
    participant Buf2 as Buffer RWX (contexto Thread Pool)
    participant TP as Windows Thread Pool

    CRT->>Core: transfiere control tras init de runtime
    Core->>Buf1: VirtualAlloc(RW) + copia clave/IV/ciphertext desde .rdata
    Core->>CAPI: CryptImportKey + CryptSetKeyParam(IV) + CryptDecrypt
    CAPI-->>Buf2: payload descifrado (573,600 bytes)
    Core->>TP: CreateThreadpoolWork(callback=0x1400123b0, context=Buf2)
    TP->>TP: SubmitThreadpoolWork / espera del pool
    Note over TP: en el binario real, el callback ejecuta el payload;<br/>en la emulación se interceptó justo antes del salto real
```

## Hallazgo 3 — la transferencia de control usa el Thread Pool de Windows

El reporte original asumía una llamada directa (`call rax`). El desensamblado + la traza de la emulación muestran que en realidad se usa **`CreateThreadpoolWork` + `SubmitThreadpoolWork`** — el callback (`0x1400123b0`) recibe como `Context` el puntero al buffer ya descifrado. Es una capa extra de indirección: dificulta el análisis dinámico ingenuo (un breakpoint en `call rax` nunca se dispara porque el "call" real ocurre dentro del callback del pool de hilos).

Se confirmó por desensamblado estático que, tras el bloque de junk code, `[rbp - 0x20]` termina siendo exactamente ese mismo puntero de `Context`, así que fue posible volcar el buffer directamente en el momento de la llamada a `CreateThreadpoolWork`, sin necesidad de dejar correr el callback real dentro del emulador.

## Resultado del volcado

- **Buffer volcado:** 573,600 bytes (`0x8c0a0`) desde el contexto pasado a `CreateThreadpoolWork`.
- **No empieza con `MZ`** (cabecera de PE clásica). Empieza con `e8 58 bc 07 00...` — una instrucción `call` de x86-64, es decir, **shellcode posicionalmente independiente**, no un ejecutable PE plano.
- Contiene una plantilla de petición HTTP en texto plano: `GET /what-is-my-ip HTTP/1.1` hacia `ipinfo.io`, con User-Agent de Chrome — indicio de un chequeo anti-sandbox / geolocalización antes de continuar con el resto de la ejecución. Ver [`03-payload-analysis.md`](03-payload-analysis.md).

## Lo que quedó sin resolver

Al decompilar (Ghidra vía `rz-ghidra`) las funciones involucradas (`fcn.140012470`, `fcn.140012230`) se confirmó parte de la lógica de asignación de memoria y un **bucle de inversión de bytes in-place** condicionado por flags — pero **no se logró aislar la instrucción exacta** dentro de esas funciones donde ocurren las llamadas a la CryptoAPI (aparecen resueltas en la traza dinámica del emulador, pero no como símbolos nombrados en el desensamblado estático de esta sesión). Documentado como línea de continuación para quien retome el análisis.
