param([string]$file)
$b = [System.IO.File]::ReadAllBytes($file)
# find "IDAT" occurrences and their length fields; collect IDAT payload by scanning
$payload = New-Object System.Collections.Generic.List[byte]
for ($i = 8; $i -lt $b.Length - 8; $i++) {
    if ($b[$i] -eq 0x49 -and $b[$i+1] -eq 0x44 -and $b[$i+2] -eq 0x41 -and $b[$i+3] -eq 0x54) {
        $clen = [int]($b[$i-4] -shl 24) + ($b[$i-3] -shl 16) + ($b[$i-2] -shl 8) + $b[$i-1]
        if ($clen -gt 0 -and $i + 4 + $clen -le $b.Length) {
            Write-Host ("IDAT @{0} len={1}" -f ($i-4), $clen)
            $payload.AddRange([byte[]]$b[($i+4)..($i+3+$clen)])
            $i += 4 + $clen
        }
    }
}
Write-Host "total idat bytes: $($payload.Count)"
$raw = $payload.ToArray()
Write-Host ("zlib head: {0:x2} {1:x2}" -f $raw[0], $raw[1])
$ms = New-Object System.IO.MemoryStream($raw, 2, $raw.Length - 2)
$ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
$out = New-Object System.IO.MemoryStream
try { $ds.CopyTo($out) } catch { Write-Host "inflate error: $_" }
Write-Host "inflated raw bytes: $($out.Length)"
foreach ($w in 128,256,512,620,768,876,1024,1280,2048) {
    $st = $w*4+1
    if (($out.Length % $st) -eq 0) { Write-Host "RGBA candidate: w=$w h=$($out.Length/$st)" }
    $st3 = $w*3+1
    if (($out.Length % $st3) -eq 0) { Write-Host "RGB candidate: w=$w h=$($out.Length/$st3)" }
}
