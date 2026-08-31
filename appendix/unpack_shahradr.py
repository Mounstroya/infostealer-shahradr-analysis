#!/usr/bin/env python3
"""
Dynamic unpacking of shahradr_clean.exe via speakeasy (Unicorn-based Win32 emulator).

Strategy:
  1. Hook VirtualAlloc to log every allocation (confirms the 0x8c0f0-byte RWX buffer).
  2. Hook dynamic code execution (fires automatically the moment EIP/RIP jumps into a
     VirtualAlloc'd region) -- this is the payload becoming live after `call rax`.
  3. Also hook the known call-rax address (0x14001240f) as a belt-and-braces fallback.
  4. On first trigger, dump the buffer to ./payload_unpacked.exe and stop emulation.
"""
import sys
import struct
import logging
import speakeasy
from Crypto.Cipher import AES, DES3, DES, ARC4

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s:%(name)s: %(message)s")
LOG = logging.getLogger("unpack")

BINARY = "./shahradr_clean.exe"
OUTPUT = "./payload_unpacked.exe"
SCRATCH = "./scratchpad"
CALL_RAX_ADDR = 0x14001240F
EXPECTED_SIZE = 0x8C0F0

state = {"dumped": False}


def dump_buffer(se, base, size, source):
    if state["dumped"]:
        return
    try:
        data = se.mem_read(base, size)
    except Exception as e:
        print(f"[!] mem_read(0x{base:x}, 0x{size:x}) failed: {e}")
        return
    with open(OUTPUT, "wb") as f:
        f.write(data)
    magic = data[:2]
    print(f"[+] ({source}) dumped 0x{len(data):x} bytes from 0x{base:x} -> {OUTPUT}")
    print(f"[+] first 2 bytes: {magic!r} ({'MZ - looks like a PE!' if magic == b'MZ' else 'not MZ'})")
    state["dumped"] = True


def crt_stub(emu, api_name, orig, argv):
    """
    Universal-CRT (api-ms-win-crt-*.dll) fallback: forward to speakeasy's
    built-in implementation when one exists, otherwise just report success (0)
    so the MinGW CRT init sequence doesn't fault on an unimplemented stub.
    """
    if orig is not None:
        return orig(argv)
    print(f"[api-stub] unimplemented {api_name}(argc={len(argv)}) -> 0")
    return 0


_fake_environ = {"addr": None}


def on_p_environ(emu, api_name, orig, argv):
    """
    __p__environ must return a valid pointer to a (char **) variable, which
    itself points to a NULL-terminated array of env strings. Returning 0
    causes the CRT init code to dereference NULL.
    """
    if _fake_environ["addr"] is None:
        env_array = SE.mem_alloc(8, tag="fake.environ.array")
        SE.mem_write(env_array, b"\x00" * 8)  # single NULL terminator entry
        env_var = SE.mem_alloc(8, tag="fake.environ.var")
        SE.mem_write(env_var, env_array.to_bytes(8, "little"))
        _fake_environ["addr"] = env_var
        print(f"[api-fix] {api_name}: fabricated empty environ at 0x{env_var:x} -> [0x{env_array:x}] -> NULL")
    return _fake_environ["addr"]


# --- Real Microsoft CryptoAPI (CAPI) emulation --------------------------------
# speakeasy models CryptAcquireContext* natively but not CryptImportKey /
# CryptDecrypt / CryptSetKeyParam. We implement them for real (not stubs) so
# the payload buffer actually gets decrypted with the malware's own key.

ALG_NAMES = {
    0x6601: "CALG_DES",
    0x6603: "CALG_3DES",
    0x6604: "CALG_3DES_112",
    0x6801: "CALG_RC4",
    0x660E: "CALG_AES_128",
    0x660F: "CALG_AES_192",
    0x6610: "CALG_AES_256",
}
KP_MODE = 4
KP_IV = 1
CRYPT_MODE_CBC = 1
CRYPT_MODE_ECB = 2
CRYPT_MODE_OFB = 3
CRYPT_MODE_CFB = 4

_crypt_keys = {}       # fake handle -> dict(alg, key, mode, iv, rc4_cipher)
_next_key_handle = [0x1000]


def on_CryptImportKey(emu, api_name, orig, argv):
    hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey = argv[:6]
    blob = SE.mem_read(pbData, dwDataLen)
    bType, bVersion, reserved, aiKeyAlg = struct.unpack_from("<BBHI", blob, 0)
    alg_name = ALG_NAMES.get(aiKeyAlg, hex(aiKeyAlg))
    if bType == 8:  # PLAINTEXTKEYBLOB
        (dwKeySize,) = struct.unpack_from("<I", blob, 8)
        key_bytes = blob[12:12 + dwKeySize]
    else:
        key_bytes = blob[8:]  # best-effort fallback
    handle = _next_key_handle[0]
    _next_key_handle[0] += 1
    _crypt_keys[handle] = {"alg": aiKeyAlg, "key": key_bytes, "mode": CRYPT_MODE_CBC, "iv": None}
    SE.mem_write(phKey, handle.to_bytes(8, "little"))
    print(f"[capi] CryptImportKey: bType={bType} alg={alg_name} keylen={len(key_bytes)} "
          f"key={key_bytes.hex()} -> hKey=0x{handle:x}")
    return 1


def on_CryptSetKeyParam(emu, api_name, orig, argv):
    hKey, dwParam, pbData, dwFlags = argv[:4]
    st = _crypt_keys.get(hKey)
    if st is None:
        return 1
    if dwParam == KP_IV:
        iv = SE.mem_read(pbData, 16)
        st["iv"] = iv
        print(f"[capi] CryptSetKeyParam(KP_IV) hKey=0x{hKey:x} iv={iv.hex()}")
    elif dwParam == KP_MODE:
        (mode,) = struct.unpack("<I", SE.mem_read(pbData, 4))
        st["mode"] = mode
        print(f"[capi] CryptSetKeyParam(KP_MODE) hKey=0x{hKey:x} mode={mode}")
    return 1


def _decrypt(st, data: bytes) -> bytes:
    alg = st["alg"]
    key = st["key"]
    mode = st.get("mode", CRYPT_MODE_CBC)
    iv = st.get("iv")
    if alg == 0x6801:  # RC4
        if "rc4" not in st:
            st["rc4"] = ARC4.new(key)
        return st["rc4"].decrypt(data)
    if alg in (0x660E, 0x660F, 0x6610):  # AES-128/192/256
        if mode == CRYPT_MODE_ECB:
            cipher = AES.new(key, AES.MODE_ECB)
        else:
            cipher = AES.new(key, AES.MODE_CBC, iv=iv or (b"\x00" * 16))
        return cipher.decrypt(data)
    if alg == 0x6603:  # 3DES
        cipher = DES3.new(key, DES3.MODE_CBC if mode != CRYPT_MODE_ECB else DES3.MODE_ECB,
                           iv=iv or (b"\x00" * 8)) if mode != CRYPT_MODE_ECB else DES3.new(key, DES3.MODE_ECB)
        return cipher.decrypt(data)
    if alg == 0x6601:  # DES
        cipher = DES.new(key, DES.MODE_CBC, iv=iv or (b"\x00" * 8)) if mode != CRYPT_MODE_ECB \
            else DES.new(key, DES.MODE_ECB)
        return cipher.decrypt(data)
    print(f"[capi] WARNING: unhandled algorithm 0x{alg:x}, returning ciphertext unchanged")
    return data


def on_CryptDecrypt(emu, api_name, orig, argv):
    hKey, hHash, final, dwFlags, pbData, pdwDataLen = argv[:6]
    (data_len,) = struct.unpack("<I", SE.mem_read(pdwDataLen, 4))
    ciphertext = SE.mem_read(pbData, data_len)
    print(f"[capi] CryptDecrypt INPUT pbData=0x{pbData:x} len=0x{data_len:x} "
          f"first32={ciphertext[:32].hex()} last16={ciphertext[-16:].hex()} "
          f"nonzero_bytes={sum(1 for b in ciphertext if b)}/{len(ciphertext)}")
    with open(f"{SCRATCH}/captured_ciphertext.bin", "wb") as _f:
        _f.write(ciphertext)
    st = _crypt_keys.get(hKey)
    if st is None:
        print(f"[capi] CryptDecrypt: unknown hKey=0x{hKey:x}, passthrough")
        return 1
    print(f"[capi] decrypt-state: alg=0x{st['alg']:x} key={st['key'].hex()} mode={st['mode']} iv={(st['iv'] or b'').hex()}")
    plaintext = _decrypt(st, ciphertext)
    # strip PKCS7 padding on the final block-cipher call
    if final and st["alg"] != 0x6801 and plaintext:
        pad = plaintext[-1]
        if 1 <= pad <= 16 and plaintext[-pad:] == bytes([pad]) * pad:
            plaintext = plaintext[:-pad]
    SE.mem_write(pbData, plaintext)
    SE.mem_write(pdwDataLen, struct.pack("<I", len(plaintext)))
    print(f"[capi] CryptDecrypt hKey=0x{hKey:x} final={final} len=0x{data_len:x} "
          f"first16={plaintext[:16].hex()}")
    return 1


def on_capi_noop_ok(emu, api_name, orig, argv):
    return 1


def on_virtualalloc(emu, api_name, orig, argv):
    rv = orig(argv) if orig else 0
    # argv: lpAddress, dwSize, flAllocationType, flProtect
    size = argv[1] if len(argv) > 1 else 0
    print(f"[api] {api_name}(size=0x{size:x}) -> 0x{rv:x}")
    return rv


def on_dyn_code(mm):
    base = mm.get_base()
    size = mm.get_size()
    print(f"[dyncode] execution entered dynamic region base=0x{base:x} size=0x{size:x} tag={mm.tag}")
    dump_buffer(SE, base, max(size, EXPECTED_SIZE), "dyn_code_hook")
    if state["dumped"]:
        SE.stop()


def on_call_rax(se, addr, size, ctx):
    rax = se.reg_read("rax")
    print(f"[code] hit call-rax site 0x{addr:x}, rax=0x{rax:x}")
    dump_buffer(se, rax, EXPECTED_SIZE, "code_hook@call_rax")
    if state["dumped"]:
        se.stop()
        return False
    return True


SE = speakeasy.Speakeasy(logger=LOG, debug=False)
SE.add_api_hook(crt_stub, module="api-ms-win-crt-*", api_name="*", argc=8)
SE.add_api_hook(on_p_environ, module="api-ms-win-crt-environment-l1-1-0", api_name="__p__environ", argc=0)
SE.add_api_hook(on_p_environ, module="api-ms-win-crt-environment-l1-1-0", api_name="__p__wenviron", argc=0)
SE.add_api_hook(on_CryptImportKey, module="advapi32", api_name="CryptImportKey", argc=6)
SE.add_api_hook(on_CryptSetKeyParam, module="advapi32", api_name="CryptSetKeyParam", argc=4)
SE.add_api_hook(on_CryptDecrypt, module="advapi32", api_name="CryptDecrypt", argc=6)
SE.add_api_hook(on_capi_noop_ok, module="advapi32", api_name="CryptDestroyKey", argc=1)
SE.add_api_hook(on_capi_noop_ok, module="advapi32", api_name="CryptReleaseContext", argc=2)
SE.add_api_hook(on_capi_noop_ok, module="advapi32", api_name="CryptGetKeyParam", argc=4)

_fake_handle = [0x9000]


def on_fake_handle(emu, api_name, orig, argv):
    _fake_handle[0] += 1
    print(f"[api-stub] {api_name}(argc={len(argv)}) -> fake handle 0x{_fake_handle[0]:x}")
    return _fake_handle[0]


for _tp_api, _argc in [
    ("CloseThreadpoolWork", 1),
    ("WaitForThreadpoolWorkCallbacks", 2), ("CreateThreadpool", 1), ("CloseThreadpool", 1),
    ("SetThreadpoolThreadMaximum", 2), ("SetThreadpoolThreadMinimum", 2),
    ("SetThreadpoolCallbackPool", 2), ("InitializeThreadpoolEnvironment", 1),
    ("DestroyThreadpoolEnvironment", 1), ("SetThreadpoolCallbackRunsLong", 1),
]:
    SE.add_api_hook(on_fake_handle, module="kernel32", api_name=_tp_api, argc=_argc)

# The unpacker schedules its final jump-into-decrypted-buffer via the Windows
# thread pool (CreateThreadpoolWork + SubmitThreadpoolWork) instead of calling
# it directly. speakeasy doesn't model thread pools, so nothing would ever
# actually invoke that callback. We emulate the dispatch ourselves: capture
# (callback, context) from CreateThreadpoolWork, then on SubmitThreadpoolWork
# manually set up the PTP_WORK_CALLBACK(Instance, Context, Work) convention
# and resume emulation at the callback -- which is exactly the code that does
# `call rax` into the unpacked buffer, so our existing code_hook will fire.
_tp_work = {}
_tp_counter = [0x9000]


def on_CreateThreadpoolWork(emu, api_name, orig, argv):
    callback, context, environ = argv[0], argv[1], argv[2]
    _tp_counter[0] += 1
    h = _tp_counter[0]
    _tp_work[h] = (callback, context)
    print(f"[tp] CreateThreadpoolWork callback=0x{callback:x} context=0x{context:x} -> handle=0x{h:x}")
    # Static analysis of the callback (0x1400123b0) proves that after its
    # junk-code obfuscation resolves, [rbp-0x20] == Context, and it does
    # `mov rax, [rbp-0x20] ; call rax`. So the buffer this thread-pool work
    # item targets *is* the fully-prepared unpacked payload already -- we
    # don't need to actually invoke the callback (which risks corrupting
    # emulator state via reentrant emu_start); just dump Context directly.
    dump_buffer(SE, context, 0x8C0A0, "CreateThreadpoolWork.context")
    return h


def on_SubmitThreadpoolWork(emu, api_name, orig, argv):
    return argv[0]


SE.add_api_hook(on_CreateThreadpoolWork, module="kernel32", api_name="CreateThreadpoolWork", argc=3)
SE.add_api_hook(on_SubmitThreadpoolWork, module="kernel32", api_name="SubmitThreadpoolWork", argc=1)

# Trace every write into the first 0x100 bytes of the RWX buffer (0xdd000) to
# find out how/whether the loader's self-pointer header field gets patched
# before the buffer is handed to CreateThreadpoolWork.
RWX_BASE = 0xDD000


def on_rwx_header_write(se, access, addr, size, value, ctx):
    print(f"[memw] write addr=0x{addr:x} (rwx+0x{addr-RWX_BASE:x}) size={size} value=0x{value:x}")
    return True


SE.add_mem_write_hook(on_rwx_header_write, begin=RWX_BASE, end=RWX_BASE + 0x100)
SE.add_api_hook(on_virtualalloc, module="kernel32", api_name="VirtualAlloc")
SE.add_dyn_code_hook(on_dyn_code)
SE.add_code_hook(on_call_rax, begin=CALL_RAX_ADDR, end=CALL_RAX_ADDR)

module = SE.load_module(BINARY)
print(f"[*] Loaded {BINARY}, base=0x{module.base:x}, entry point 0x{module.ep:x}")

try:
    SE.run_module(module)
except Exception as e:
    print(f"[!] Emulation raised: {e}")

for label, addr, size in [("rw_0x50000_0x8c0f0", 0x50000, EXPECTED_SIZE),
                           ("rwx_0xdd000_0x8c0a0", 0xDD000, 0x8C0A0)]:
    try:
        data = SE.mem_read(addr, size)
        nz = sum(1 for b in data if b)
        out = f"{SCRATCH}/dump_{label}.bin"
        with open(out, "wb") as f:
            f.write(data)
        print(f"[dump] {label}: nonzero={nz}/{len(data)} first32={data[:32].hex()} -> {out}")
    except Exception as e:
        print(f"[dump] {label}: mem_read failed: {e}")

if not state["dumped"]:
    print("[!] Target buffer was never dumped. Emulation may have diverged or hit an unimplemented API.")
    sys.exit(1)
else:
    print("[+] SUCCESS")
