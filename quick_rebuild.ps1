cd .\abyss_core
$env:CGO_ENABLED = "1"
./build_dll_debug.ps1
cd ..

cd .\abyss_engine
./build_debug.ps1
./export_debug.ps1
cd ..