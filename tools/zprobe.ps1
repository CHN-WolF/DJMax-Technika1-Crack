param([string]$file, [string]$offs)
$b = [System.IO.File]::ReadAllBytes($file)
foreach ($off in ($offs -split ',')) {
    $off = [long]$off
    $len = $b.Length - $off
    $ms = New-Object System.IO.MemoryStream($b, [int]$off, $len)
    $ds = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $out = New-Object System.IO.MemoryStream
    try {
        $ds.CopyTo($out)
        $hex = ($out.ToArray()[0..15] | ForEach-Object { $_.ToString('x2') }) -join ' '
        Write-Host ("zlib @{0}: inflated={1} first={2}" -f $off, $out.Length, $hex)
    } catch { Write-Host ("zlib @{0}: FAIL ({1})" -f $off, $_.Exception.Message) }
    $ds.Dispose()
}
