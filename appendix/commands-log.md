# Log de comandos clave

Comandos representativos ejecutados durante la investigación (rutas de usuario generalizadas a `$HOME`/`$SCRATCH` — no son las rutas reales del analista). No es un log exhaustivo de las ~100 llamadas a herramientas de la sesión original, sino los comandos que marcan cada paso importante.

## Reconocimiento del entorno

```bash
ls -la /tmp/malware_extract/
file /tmp/malware_extract/shahradr.exe
sudo -n true 2>&1 || echo "no passwordless sudo"
find / -iname "*.AppImage" 2>/dev/null
find /tmp/squashfs-root -iname "*ghidra*"
```

## Recorte del binario

```bash
dd if=/tmp/malware_extract/shahradr.exe of=/tmp/shahradr_clean.exe bs=1M count=5
```

## Entorno de emulación

```bash
python3 -m venv $SCRATCH/malware_venv
source $SCRATCH/malware_venv/bin/activate
pip install speakeasy-emulator unicorn==1.0.2 capstone pefile lief pycryptodome setuptools
```

## Análisis estático headless con rizin / Ghidra

```bash
RZ=/tmp/squashfs-root/usr/bin/rizin
export LD_LIBRARY_PATH=/tmp/squashfs-root/usr/lib:$LD_LIBRARY_PATH
export SLEIGHHOME=/tmp/squashfs-root/usr/lib/rizin/plugins/rz_ghidra_sleigh

# Desensamblado en una dirección puntual
$RZ -q -c "pd 40 @ 0x1400123b0" /tmp/shahradr_clean.exe

# Decompilación con el plugin de Ghidra
$RZ -q -c "aa; s 0x140012470; pdg" /tmp/shahradr_clean.exe
```

## Ejecución del script de emulación (iterativo)

```bash
source $SCRATCH/malware_venv/bin/activate
python3 $SCRATCH/unpack_shahradr.py
```

(el contenido de `unpack_shahradr.py` no se incluye en este repositorio — ver [`../tools-used.md`](../tools-used.md) para su descripción funcional)

## Extracción de strings del payload desempaquetado

```bash
strings -n 5 /tmp/payload_unpacked.exe | head -100
strings -e l /tmp/payload_unpacked.exe   # UTF-16LE
```
