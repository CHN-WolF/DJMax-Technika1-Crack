param([string]$file)
$b = [System.IO.File]::ReadAllBytes($file)
$p = 8
while ($p + 12 -le $b.Length) {
    $clen = [int]($b[$p] -shl 24) + ($b[$p+1] -shl 16) + ($b[$p+2] -shl 8) + $b[$p+3]
    $type = [System.Text.Encoding]::ASCII.GetString($b, $p + 4, 4)
    Write-Host ("chunk @{0} type={1} len={2}" -f $p, $type, $clen)
    if ($type -eq 'IEND') { break }
    $p += 12 + $clen
}
