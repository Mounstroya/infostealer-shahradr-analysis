# 03 — Análisis del payload desempaquetado

## Qué es el buffer volcado

El buffer de 573,600 bytes obtenido en la fase de desempaquetado ([`02-unpacking.md`](02-unpacking.md)) **no es un PE clásico**. Es un *stub de mapeo manual de PE* (manual PE mapper), una técnica común en malware para evitar que el payload final quede como un ejecutable "normal" detectable por firma:

1. Es código de posición independiente: usa el truco clásico `call`/`pop` para autolocalizarse en memoria (obtener su propia dirección base sin depender de dónde lo cargó el sistema).
2. Una vez que se conoce su propia dirección, el stub está preparado para leer `e_lfanew` (el campo de la cabecera DOS de un PE, en el offset `0x3c`, que apunta a la cabecera NT real) **de una imagen PE referenciada por puntero**, no de sí mismo.
3. Ese puntero (esperado en el offset `0xD` del buffer) es el que normalmente se escribe justo antes de que el mapeador lo use — y en el volcado capturado todavía vale cero, porque la intercepción ocurrió un paso antes de que el packer completara ese último parche.

En otras palabras: **el stub-cargador está completo e intacto**, pero le falta el "objetivo" (la imagen PE final con las funciones de robo) porque el volcado se tomó justo antes de que esa referencia se completara.

## Evidencia de anti-análisis / anti-sandbox

Extrayendo strings ASCII del buffer se encontró:

```
GET /what-is-my-ip HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
```

Esto apunta a una petición hacia `ipinfo.io/what-is-my-ip` — un patrón típico de **chequeo de geolocalización / fingerprinting de red** antes de decidir si continuar con la ejecución completa (muchas familias de InfoStealer evitan ejecutarse si detectan rangos de IP de datacenters/sandboxes conocidos, o restringen su actividad a ciertos países).

El resto de los strings extraídos del buffer son mayormente ruido de alta entropía (fragmentos cortos, no interpretables) — consistente con que la mayor parte del buffer sigue siendo datos empaquetados/ofuscados a la espera del parche final descrito arriba, y no código o strings legibles todavía.

## Qué falta para llegar a las funciones de robo

Para decompilar las funciones reales de robo de datos (credenciales de navegadores vía DPAPI, bases SQLite3 de cookies/passwords, rutas de perfiles) haría falta:

1. Localizar en `fcn.140012470` (o una subfunción no explorada) el punto exacto donde se escribe el puntero en el offset `0xD` del buffer, antes de que el mapeador lo consuma.
2. Completar la emulación un paso más allá de `CreateThreadpoolWork`, dejando correr el callback real (`0x1400123b0`) con el puntero ya parchado, para que el mapeador reconstruya el PE final en memoria.
3. Volcar esa imagen PE ya reconstruida (con cabeceras corregidas si es necesario) y decompilarla con Ghidra/rizin.

Esto quedó como trabajo pendiente — ver [`../README.md`](../README.md#limitaciones-y-trabajo-pendiente) y [`../data-exfiltrated.md`](../data-exfiltrated.md).
