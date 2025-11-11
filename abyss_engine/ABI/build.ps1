python ./RenderActionNumberGen.py
./build_protobuf.ps1

cd ../external_utils/renderactiongen
./autobuild
cd ../../ABI
./renderactiongen.exe RenderAction.proto
./renderactiongen.exe UIAction.proto
