if (Test-Path -Path ./release) {
    Remove-Item ./release -Recurse -Force
}

Write-Output "Auto-generating C# (abyss_engine <=> abyss_ui) ABI"
Set-Location ./ABI
./build.ps1
Set-Location ..

Write-Output "Updating build version for AbyssCLI.exe"
python.exe ./Tool/ExternData.py

Write-Output "Building AbyssCLI.exe"
dotnet publish -c Release -r win-x64 --self-contained true -o ./release/win-x64