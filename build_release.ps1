if (Test-Path -Path ./release) {
    Remove-Item ./release -Recurse -Force
}

# building libraries
Write-Output "Building abyss_core (abyssnet.dll)"
Set-Location abyss_core
./build_release.ps1
Set-Location ..

Write-Output "Building abyss_engine (AbyssCLI.exe)"
Set-Location abyss_engine
./build_release.ps1
Set-Location ..

Write-Output "Building keygen.exe"
Set-Location ./keygen
./build_release.ps1
Set-Location ..

# building AbyssUI
Write-Output "Preparing dependencies for AbyssUI"
Remove-Item -Path ./AbyssUI/Assets/Host/ABI -Recurse -Force
Copy-Item -Path ./abyss_engine/ABI -Destination ./AbyssUI/Assets/Host/ABI -Recurse

Write-Output "Building AbyssUI"
Set-Location ./AbyssUI
./build_release.ps1
Set-Location ..

# now, AbyssUIBuild is ready. We provide dependencies.

Write-Output "Copying AbyssCLI to release folder"
Copy-Item -Path ./abyss_engine/release/win-x64 -Destination ./release/win-x64/AbyssCLI -Recurse

Write-Output "Copying abyssnet.dll to release folder"
Copy-Item -Path ./abyss_core/release/win-amd64/abyssnet.dll -Destination ./release/win-x64/AbyssCLI/abyssnet.dll

Write-Output "Copying keygen.exe to release folder"
Copy-Item -Path ./keygen/release/win-amd64/keygen.exe -Destination ./release/win-x64/keygen.exe