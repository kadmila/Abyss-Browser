$env:CGO_ENABLED = "1"

Write-Output "Preparing dependencies for AbyssUnity"
./build_debug.ps1
New-Item -Path ./AbyssUnity/Assets/Plugins -ItemType Directory -Force

Write-Output "Downloading Protobuf .net2.0 nuget packages for unity"
New-Item -ItemType Directory -Name nuget
Set-Location ./nuget

curl -o protobuf.zip https://globalcdn.nuget.org/packages/google.protobuf.3.34.0-rc1.nupkg?packageVersion=3.34.0-rc1
curl -o system.memory.zip https://globalcdn.nuget.org/packages/system.memory.4.6.3.nupkg?packageVersion=4.6.3
curl -o system.buffers.zip https://globalcdn.nuget.org/packages/system.buffers.4.6.1.nupkg?packageVersion=4.6.1
curl -o system.numerics.vectors.zip https://globalcdn.nuget.org/packages/system.numerics.vectors.4.6.1.nupkg?packageVersion=4.6.1
curl -o system.runtime.compilerservices.unsafe.zip https://globalcdn.nuget.org/packages/system.runtime.compilerservices.unsafe.6.1.2.nupkg?packageVersion=6.1.2

Expand-Archive -Path ./protobuf.zip -DestinationPath ./protobuf
Expand-Archive -Path ./system.memory.zip -DestinationPath ./system.memory
Expand-Archive -Path ./system.buffers.zip -DestinationPath ./system.buffers
Expand-Archive -Path ./system.numerics.vectors.zip -DestinationPath ./system.numerics.vectors
Expand-Archive -Path ./system.runtime.compilerservices.unsafe.zip -DestinationPath ./system.runtime.compilerservices.unsafe

Move-Item -Path ./protobuf/lib/netstandard2.0/Google.Protobuf.dll ../AbyssUnity/Assets/Plugins/Google.Protobuf.dll
Move-Item -Path ./system.memory/lib/netstandard2.0/System.Memory.dll ../AbyssUnity/Assets/Plugins/System.Memory.dll
Move-Item -Path ./system.buffers/lib/netstandard2.0/System.Buffers.dll ../AbyssUnity/Assets/Plugins/System.Buffers.dll
Move-Item -Path ./system.numerics.vectors/lib/netstandard2.0/System.Numerics.Vectors.dll ../AbyssUnity/Assets/Plugins/System.Numerics.Vectors.dll
Move-Item -Path ./system.runtime.compilerservices.unsafe/lib/netstandard2.0/System.Runtime.CompilerServices.Unsafe.dll ../AbyssUnity/Assets/Plugins/System.Runtime.CompilerServices.Unsafe.dll

Set-Location ..
Remove-Item nuget -Force -Recurse

Set-Location ./AbyssUnity
Copy-Item ".\build.config.origin" ".\build.config"
Set-Location ..

# TODO: create unity project and import abyss_unity
# Create AbyssUI/build.config file.