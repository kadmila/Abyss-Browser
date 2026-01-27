cd abyss_core
./build_dll.ps1
cd ..
cd abyss_engine
./build_release.ps1
./export_release.ps1
cd ..

cd .\keygen
go build -o .\keygen.exe .
cd ..

Write-Output "Copying keygen.exe to \AbyssUI"
Copy-Item -Path .\keygen\keygen.exe -Destination .\AbyssUI\

Write-Output "Copying keygen.exe to \AbyssUIBuild"
Copy-Item -Path .\keygen\keygen.exe -Destination .\AbyssUIBuild\