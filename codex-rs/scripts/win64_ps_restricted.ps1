param(
  [string[]]$Command,
  [int]$Depth = 3,
  [string]$Username = "SandboxUserPS",
  [string]$PasswordPlain = "YourStrongP@ssw0rd"
)

$secPass = ConvertTo-SecureString $PasswordPlain -AsPlainText -Force
if (-not (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $Username -Password $secPass -PasswordNeverExpires -UserMayNotChangePassword
}
Add-LocalGroupMember -Group Users -Member $Username -ErrorAction SilentlyContinue

$origPath    = (Get-Location).ProviderPath
$sandboxRoot = Join-Path $origPath "sandbox"
if (Test-Path $sandboxRoot) {
    Remove-Item $sandboxRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $sandboxRoot | Out-Null

$prevPath = $sandboxRoot
for ($i = 1; $i -le $Depth; $i++) {
    $dest = Join-Path $sandboxRoot "copy_$i"
    Copy-Item $prevPath $dest -Recurse -Force
    $prevPath = $dest
}

$cmdLine = $Command -join ' '
if ($cmdLine -match '\bcd\s+\.\.') {
    Write-Error "cd .. is not allowed."
    exit 1
}

Write-Host "Launching sandbox as $Username in $sandboxRoot" -ForegroundColor Green
$cred = New-Object System.Management.Automation.PSCredential("$env:COMPUTERNAME\$Username", $secPass)
$outputFile = Join-Path $sandboxRoot "ps_output.txt"
Start-Process -FilePath pwsh.exe -ArgumentList "-NoProfile","-Command","Set-Location -LiteralPath '$sandboxRoot'; $cmdLine" -Credential $cred -NoNewWindow -Wait -RedirectStandardOutput $outputFile -RedirectStandardError $outputFile
Get-Content $outputFile
