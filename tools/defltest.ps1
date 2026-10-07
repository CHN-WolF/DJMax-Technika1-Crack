param([string]$file, [long]$maxoff = 1048576)
$b = [System.IO.File]::ReadAllBytes($file)
$found = 0
for ($off = 0x80; $off -lt [Math]::Min($maxoff, $b.Length - 70000); $off += 16) {
    # quick entropy-ish skip: deflate blocks rarely start 0x00
    if ($b[$off] -eq 0) { continue }
    foreach ($mode in 'Deflate','GZip') {
        try {
            $ms = New-Object System.IO.MemoryStream($b, [int]$off, 65536)
            if ($mode -eq 'Deflate') { $ds = New-Object System.IO.Compression.DeflateStream($ms,[System.IO.Compression.CompressionMode]::Decompress) }
            else { $ds = New-Object System.IO.Compression.GZipStream($ms,[System.IO.Compression.CompressionMode]::Decompress) }
            $out = New-Object byte[] 262144
            $n = 0
            try { $n = $ds.Read($out,0,262144) } catch { }
            $ds.Dispose(); $ms.Dispose()
            if ($n -gt 64) {
                $hex = ($out[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' '
                Write-Host ("HIT off={0} mode={1} n={2} first={3}" -f $off,$mode,$n,$hex)
                $found++
                if ($found -gt 6) { exit }
            }
        } catch { }
    }
}
Write-Host "scan done, found=$found"
