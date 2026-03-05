param([string]$Path="Main.daml")

if (!(Test-Path $Path)) { Write-Host "File not found: $Path"; exit 1 }

$c = Get-Content $Path -Raw

$idx = $c.IndexOf("module ")
if ($idx -gt 0) { $c = $c.Substring($idx) }

$c = [regex]::Replace($c, "[\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D]", "-")
$c = $c.Replace([char]0x2500, "-")

$c = [regex]::Replace($c, "^(?s).*?\bmodule\s+Main\s+where\s*", "module Main where`r`n`r`n")

$c = [regex]::Replace($c, "allocatePartyWithHint\s+name\s+\(PartyIdHint\s+name\)", "allocatePartyByHint (PartyIdHint name)")

Set-Content -Path $Path -Value $c -Encoding utf8
Write-Host "Patched: $Path"
