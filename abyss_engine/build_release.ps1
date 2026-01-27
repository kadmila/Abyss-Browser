Write-Output "building AbyssCLI.exe"

cd ./ABI
./build.ps1
cd ..

python.exe ./Tool/ExternData.py

#dotnet build AbyssCLI.csproj --configuration Release
dotnet publish -c Release -r win-x64 --self-contained true