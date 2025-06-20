Remove-LocalUser -Name SandboxUserPS -ErrorAction SilentlyContinue
Remove-Item "$PWD\sandbox" -Recurse -Force -ErrorAction SilentlyContinue
