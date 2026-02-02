$env:CGO_ENABLED = "1"

Write-Output "Preparing dependencies for AbyssUnity"
./build_debug.ps1
Copy-Item ./abyss_engine/bin/Debug/net8.0/Google.Protobuf.dll ./AbyssUnity/Assets/Plugins/Google.Protobuf.dll

Set-Location ./AbyssUnity
Copy-Item ".\build.config.origin" ".\build.config"
Set-Location ..

# TODO: create unity project and import abyss_unity
# Create AbyssUI/build.config file.