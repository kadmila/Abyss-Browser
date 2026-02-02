$env:CGO_ENABLED = "1"

Write-Output "Preparing dependencies for AbyssUnity"
Set-Location ./abyss_engine/ABI
./build.ps1
Set-Location ../..
Copy-Item -Path ./abyss_engine/ABI -Destination ./AbyssUnity/Assets/Host/ABI -Recurse

Set-Location ./AbyssUnity
Copy-Item ".\build.config.origin" ".\build.config"
Set-Location ..

# TODO: create unity project and import abyss_unity
# Create AbyssUI/build.config file.