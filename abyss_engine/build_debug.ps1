
Write-Output "Auto-generating C# (abyss_engine <=> abyss_ui) ABI"
Set-Location ./ABI
./build.ps1
Set-Location ..

Write-Output "Updating build version for AbyssCLI.exe"
python.exe ./Tool/ExternData.py

Write-Output "Building AbyssCLI.exe"
Remove-Item -Path ./bin/Debug -Recurse -Force
dotnet build AbyssCLI.csproj -c Debug
