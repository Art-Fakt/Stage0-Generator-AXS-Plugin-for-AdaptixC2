# Stage0 Cradle Generator — AdaptixC2 Plugin

> AXS plugin for AdaptixC2 that encrypts agent payloads and wraps them into ready-to-deploy in-memory cradles with evasion, environment keying, and polymorphic obfuscation.

## Overview

I wanted to test developping a plugin like CS Agressor Scripts for AdaptixC2 when I'm seeing that the AdaptixC2 WIKI is well documented, so here it is...

Stage0 Generator takes a raw agent payload (shellcode `.bin` or `.exe`) generated from an AdaptixC2 listener, encrypts it with XOR, and injects it into an external cradle template. The output is a self-contained script (PowerShell, Python, or WSF polyglot) that decrypts and executes the payload entirely in memory at runtime.

Everything is driven through a single GUI dialog accessible from the main menu bar.

<p align="center">
  <img src="form.png" alt="Stage0 Generator — Plugin Demo" width="720"/>
</p>

## Features

### Output Formats

| Format | Extension | Description |
|---|---|---|
| **PowerShell** | `.ps1` | Native Windows scripting — supports AMSI/ETW bypass, .NET reflection, and Win32 API shellcode injection |
| **Python** | `.py` | Cross-platform cradle using `ctypes` for Windows API calls (`VirtualAlloc`, `CreateThread`) |
| **Polyglot WSF** | `.wsf` | VBScript + JScript polyglot that launches a hidden PowerShell process with `-EncodedCommand`. Double-click execution, bypasses some email/web filters |

### Payload Types

- **Shellcode (.bin)** — Raw shellcode injected into memory via `VirtualAlloc` + execution primitive
- **Executable (.exe)** — Full PE loaded either via .NET `Assembly.Load()` reflection or drop-to-disk with self-cleanup

### Execution Methods (Shellcode)

| Method | Technique | Notes |
|---|---|---|
| **Classic** | `VirtualAlloc` RWX → `CreateThread` → `WaitForSingleObject` | Standard shellcode execution |
| **Callback** | `VirtualAlloc` → shellcode delivered through a Windows API callback | Avoids direct `CreateThread` call |

Callback implementations:
- **Python**: `EnumDesktopWindows` with `WNDENUMPROC` function pointer
- **PowerShell**: `EnumChildWindows` with `VirtualProtect` RW→RX transition (no RWX)

### EXE Loading Methods (PowerShell only)

| Method | Technique |
|---|---|
| **Reflective** | `[System.Reflection.Assembly]::Load()` — fully in-memory, no disk write |
| **Drop + Execute** | Write to `%TEMP%`, execute hidden, auto-cleanup after 5 seconds |

### Encryption

- **XOR** with random or custom key (configurable length 8–128 bytes)
- Key and encrypted payload are base64-encoded and embedded in the cradle
- Decryption happens at runtime before execution

### Evasion Options

| Option | PowerShell | Python | Description |
|---|---|---|---|
| **AMSI Bypass** | ✅ | — | Patches `AmsiUtils` context pointer to `IntPtr.Zero` |
| **ETW Patching** | ✅ | — | Patches `EventProvider.m_WriteEvent` with `ret` (0xC3) to silence ETW |
| **Anti-VM** | ✅ | ✅ | Checks MAC address prefixes (VMware, VBox, Hyper-V, Parallels, Xen) and `IsProcessorFeaturePresent(31)` |
| **Anti-Debug** | ✅ | ✅ | Calls `IsDebuggerPresent()` — exits silently if debugger attached |
| **Sandbox Sleep** | ✅ | ✅ | Sleeps 3 seconds and measures elapsed time — exits if time was accelerated (fast-forward detection) |
| **Variable Randomization** | ✅ | ✅ | All variable names, function names, and class names are randomized per generation |

> For WSF output: evasion options are applied inside the inner PowerShell cradle that the WSF wraps.

### Environment Keying (Target Lock)

Lock the cradle to a specific target machine. If any check fails, the script exits silently without executing the payload.

| Field | PowerShell Check | Python Check |
|---|---|---|
| **Hostname** | `$env:COMPUTERNAME` | `socket.gethostname()` |
| **Username** | `$env:USERNAME` | `getpass.getuser()` |
| **Domain** | `$env:USERDOMAIN` | `os.environ['USERDOMAIN']` |

All three fields are optional — fill in one or more.

### Advanced Options

| Option | Description |
|---|---|
| **Payload Chunking** | Splits the base64-encoded payload blob into multiple randomly-sized variables (2000–5000 chars each) and concatenates them at runtime. Breaks static signature patterns. Variable names are randomized. |
| **Junk Code Injection** | Inserts 5–12 random dead-code statements (strings, integers, arrays, arithmetic) into the pre-checks section. Different on every generation (polymorphic). |

### Timing / Kill Date

- **Startup Delay**: configurable sleep (0–3600 seconds) before payload execution
- **Kill Date**: if the current date exceeds the specified `YYYY-MM-DD`, the cradle exits without executing

## Template Architecture

The plugin uses external template files stored in `templates/` alongside the `.axs` file. Templates use `{{PLACEHOLDER}}` markers that are replaced at generation time.

```
Stage0/
├── stage0_generator.axs          # Main plugin
└── templates/
    ├── cradle_shellcode.py        # Python — classic CreateThread
    ├── cradle_shellcode.ps1       # PowerShell — classic CreateThread
    ├── cradle_shellcode_callback.py   # Python — EnumDesktopWindows callback
    ├── cradle_shellcode_callback.ps1  # PowerShell — EnumChildWindows callback (RW→RX)
    ├── cradle_exe.py              # Python — drop + exec with atexit cleanup
    ├── cradle_exe.ps1             # PowerShell — reflection or drop (EXE_BLOCK injected)
    └── cradle_polyglot.wsf        # VBScript/JScript polyglot wrapper
```

### Template Placeholders

| Placeholder | Used In | Description |
|---|---|---|
| `{{PRE_CHECKS}}` | All cradles | Evasion, env keying, junk code block |
| `{{PAYLOAD_BLOCK}}` | All cradles | Base64 payload declaration (single blob or chunked) |
| `{{XOR_KEY_B64}}` | All cradles | Base64-encoded XOR key |
| `{{V_KEY}}`, `{{V_ENC}}`, `{{V_BUF}}`, `{{V_PTR}}`, `{{V_HT}}` | All cradles | Randomized variable names |
| `{{FN_DECRYPT}}`, `{{FN_EXECUTE}}` | All cradles | Randomized function names |
| `{{V_TMP}}`, `{{RAND_FILENAME}}` | EXE cradles | Temp path and random filename for drop |
| `{{EXE_BLOCK}}` | `cradle_exe.ps1` | Reflection or drop+execute block |
| `{{V_CB}}` | Callback PS | Randomized C# class name |
| `{{PS_ENCODED}}` | `cradle_polyglot.wsf` | UTF-16LE base64-encoded PowerShell command |
| `{{WSF_JOB}}`, `{{JSF_ENTRY}}`, `{{JSV_SHELL}}`, `{{JSV_CMD}}`, `{{VBF_CALLER}}` | WSF | Randomized WSF element/function names |

## Installation

1. Copy the `Stage0/` folder (with `templates/`) to your AdaptixC2 scripts directory
2. Load the plugin: **Adaptix Menu → Scripts → Load** → select `stage0_generator.axs`
3. **Stage0 Generator** appears in the Extensions menu bar

## Usage

1. Generate an agent payload from a listener (right-click Listener → Generate Agent)
2. Open **Stage0 Generator** from the menu bar
3. Select payload type (shellcode or EXE) and upload the file
4. Choose output format, execution method, encryption settings
5. Enable desired evasion options, environment keying, and advanced features
6. Click **Generate Cradle**
7. Review in the output preview, then **Copy to Clipboard** or **Save to File**

## Supported Tested Agents

| Agent | Architecture | Formats |
|---|---|---|
| Beacon | x64 | EXE, Shellcode (.bin) |
| Gopher | x64 | EXE |
| Kharon | x64 | EXE, Shellcode (.bin) |
| Maverick | x64 | EXE, Shellcode (.bin) |
