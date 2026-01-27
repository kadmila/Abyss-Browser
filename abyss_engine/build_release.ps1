
Write-Output "Deleting existing build"
if (Test-Path -Path ./release) {
    Remove-Item ./release -Recurse -Force
}

Write-Output "Auto-generating C# (abyss_engine <=> abyss_ui) ABI"
cd ./ABI
./build.ps1
cd ..

Write-Output "Updating build version for AbyssCLI.exe"
python.exe ./Tool/ExternData.py

Write-Output "Building AbyssCLI.exe"
dotnet publish -c Release -r win-x64 --self-contained true -o ./release/win-x64