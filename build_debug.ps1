
# building libraries
Write-Output "Building abyss_core (abyssnet.dll)"
Set-Location abyss_core
./build_debug.ps1
Set-Location ..

Write-Output "Building abyss_engine (AbyssCLI.exe)"
Set-Location abyss_engine
./build_debug.ps1
Set-Location ..

Write-Output "Building keygen.exe"
Set-Location ./keygen
./build_debug.ps1
Set-Location ..

Write-Output "Copying abyssnet.dll to abyss_engine/bin/Debug/net8.0/"
Copy-Item -Path ./abyss_core/abyssnet.dll -Destination ./abyss_engine/bin/Debug/net8.0/abyssnet.dll

Write-Output "Copying abyss_engine build to AbyssUI/AbyssCLI/"
Remove-Item -Path ./AbyssUI/Assets/Host/ABI -Recurse -Force
Copy-Item -Path ./abyss_engine/ABI -Destination ./AbyssUI/Assets/Host/ABI -Recurse
Remove-Item -Path ./AbyssUI/AbyssCLI -Recurse -Force
Copy-Item -Path ./abyss_engine/bin/Debug/net8.0 -Destination ./AbyssUI/AbyssCLI -Recurse

Write-Output "Copying keygen.exe to AbyssUI/"
Copy-Item -Path ./keygen/keygen.exe -Destination ./AbyssUI/