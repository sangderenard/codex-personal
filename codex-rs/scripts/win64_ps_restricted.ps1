param(
  [string[]]$Command,
  [int]$Depth = 3
)

$origPath    = (Get-Location).ProviderPath
$sandboxRoot = Join-Path $env:USERPROFILE "sandbox"
if (Test-Path $sandboxRoot) {
    Remove-Item $sandboxRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $sandboxRoot | Out-Null

# Set the sandbox directory owner before adjusting permissions
icacls $sandboxRoot /inheritance:r | Out-Null
icacls $sandboxRoot /grant:r "$env:USERNAME:(OI)(CI)F" | Out-Null

$prevPath = $sandboxRoot
for ($i = 1; $i -le $Depth; $i++) {
    $dest = Join-Path $sandboxRoot "copy_$i"
    Copy-Item $prevPath $dest -Recurse -Force
    $prevPath = $dest
}

if (-not $Command -or $Command.Count -eq 0) {
    Write-Error "Error: Command parameter is empty or invalid."
    exit 1
}

$cmdLine = $Command -join ' '
if ($cmdLine -match '\bcd\s+\.\.') {
    Write-Error "cd .. is not allowed."
    exit 1
}

Write-Host "Launching sandbox in $sandboxRoot" -ForegroundColor Green
$outputFile = Join-Path $sandboxRoot "ps_output.txt"
Start-Process -FilePath pwsh.exe -ArgumentList "-NoProfile","-Command","Set-Location -LiteralPath '$sandboxRoot'; $cmdLine" -NoNewWindow -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $outputFile
Get-Content $outputFile
