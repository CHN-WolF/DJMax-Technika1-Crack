# pngfix.ps1 — repair template/bogus PNG IHDR in extracted tpk assets.
# Some packs store PNGs with a boilerplate IHDR (garbage height/CRC); the IDAT
# pixel data is intact. We inflate IDAT, derive the real height from
# rawlen = h*(w*bpp+1), rewrite IHDR with correct CRC.
# usage: pngfix.ps1 <dir>   (recurses *.png)
param([string]$dir)

function Get-Crc32([byte[]]$bytes) {
    $crc = 0xFFFFFFFF
    foreach ($b in $bytes) {
        $crc = $crc -bxor $b
        for ($k = 0; $k -lt 8; $k++) { $crc = if ($crc -band 1) { ($crc -shr 1) -bxor 0xEDB88320 } else { $crc -shr 1 } }
    }
    return $crc -bxor 0xFFFFFFFF
}

$fixed = 0; $ok = 0; $bad = 0
Get-ChildItem -Path $dir -Recurse -Filter *.png | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($b.Length -lt 40) { $bad++; return }
    if ($b[0] -ne 0x89 -or $b[1] -ne 0x50) { $bad++; return }
    $w = [int]($b[16] -shl 24) + ($b[17] -shl 16) + ($b[18] -shl 8) + $b[19]
    $h = [int]($b[20] -shl 24) + ($b[21] -shl 16) + ($b[22] -shl 8) + $b[23]
    $depth = $b[24]; $ctype = $b[25]
    # verify IHDR CRC
    $ihdr = New-Object byte[] 17
    [Array]::Copy($b, 12, $ihdr, 0, 17)
    $crcStored = [uint32]($b[29] -shl 24) + ($b[30] -shl 16) + ($b[31] -shl 8) + $b[32]
    if ((Get-Crc32 $ihdr) -eq $crcStored -and $w -gt 0 -and $w -le 8192 -and $h -gt 0 -and $h -le 8192) { $ok++; return }

    # collect IDAT data
    $p = 8
    $idat = New-Object System.Collections.Generic.List[byte]
    while ($p + 12 -le $b.Length) {
        $clen = [int]($b[$p] -shl 24) + ($b[$p+1] -shl 16) + ($b[$p+2] -shl 8) + $b[$p+3]
        $type = [System.Text.Encoding]::ASCII.GetString($b, $p + 4, 4)
        if ($type -eq 'IDAT') { $idat.AddRange([byte[]]$b[($p+8)..($p+7+$clen)]) }
        if ($type -eq 'IEND') { break }
        $p += 12 + $clen
    }
    if ($idat.Count -lt 4) { $bad++; return }
    # strip zlib 2-byte header, inflate raw deflate
    $raw = $idat.ToArray()
    $ms = New-Object System.IO.MemoryStream($raw, 2, $raw.Length - 2)
    $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    try { $ds.CopyTo($out) } catch { $bad++; return }
    $rawlen = $out.Length
    $bpp = switch ($ctype) { 0 {1} 2 {3} 3 {1} 4 {2} 6 {4} default {4} }
    if ($depth -eq 16) { $bpp *= 2 }
    $stride = $w * $bpp + 1
    if ($stride -le 1 -or ($rawlen % $stride) -ne 0) {
        # stored width may also be bogus: try common widths
        $found = $false
        foreach ($w2 in 128,256,512,768,1024,1280,2048,4096) {
            $st = $w2 * $bpp + 1
            if (($rawlen % $st) -eq 0) { $w = $w2; $stride = $st; $found = $true; break }
        }
        if (-not $found) { $bad++; return }
    }
    $h = [int]($rawlen / $stride)
    if ($h -le 0 -or $h -gt 16384) { $bad++; return }
    # rewrite IHDR: width(4) height(4) keep depth/ctype/comp/filter/interlace
    $b[16] = ($w -shr 24) -band 0xff; $b[17] = ($w -shr 16) -band 0xff; $b[18] = ($w -shr 8) -band 0xff; $b[19] = $w -band 0xff
    $b[20] = ($h -shr 24) -band 0xff; $b[21] = ($h -shr 16) -band 0xff; $b[22] = ($h -shr 8) -band 0xff; $b[23] = $h -band 0xff
    [Array]::Copy($b, 12, $ihdr, 0, 17)
    $crc = Get-Crc32 $ihdr
    $b[29] = ($crc -shr 24) -band 0xff; $b[30] = ($crc -shr 16) -band 0xff; $b[31] = ($crc -shr 8) -band 0xff; $b[32] = $crc -band 0xff
    [System.IO.File]::WriteAllBytes($_.FullName, $b)
    $fixed++
}
Write-Host "ok=$ok fixed=$fixed bad=$bad"
