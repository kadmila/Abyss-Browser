# Abyss Browser
The Web Conf. 2026 Demo Track Artifact
Prototype Abyss Browser, along with a simple public peer registry.
See https://github.com/kadmila/Abyss-Browser/wiki for development guide, user guide, AML specification, and others.

# How to Run

The Release package includes an examplar peer identity private key.
Double click on AbyssUI.exe to run the Abyss browser.

To run multiple instances of the Abyss browser, copy the entire folder in different location, delete the default identity private key, and generate another private key using the command below.
The command must be executed using powershell.

```
ssh-keygen -t ed25519 -f "my_key.pem" -N '""' > $null
```

Use another file name instead of "my_key.pem".

# How to Build

This section explains how you can build & contribute to this project.

To build the binaries, you need
* go version go1.24.3 windows/amd64
* visual studio 2022 with C# .NET framework 4.8 and Unity3D dev package.
* unity 3D 2022.3.62 with Windows Build Support (IL2CPP)
* Runtime OBJ Importer package by Dummiesman from Unity Asset Store
* Input System package from Unity Registry
* protobuf (protoc in PATH) https://github.com/protocolbuffers/protobuf/releases
* 64-bit gcc in PATH

## Overview

The Abyss browser source codes are separeted in three folders:
1) abyss_core //the core networking library written in golang
2) abyss_engine //the abyss brower engine
3) abyss_unity //executable abyss browser

While abyss_core and abyss_engine directly builds within the folder, the unity project cannot be directly constructed in the abyss_unity folder.
Read the procedure below to setup the unity project.

The source code of a simple public peer registry (irublue.com) is provided in ./x_public_peer_registry folder.
Unfortunately, you cannot build and deploy irublue.com locally.
The codes are only for reference.

## Initial Setup

Before starting the project setup, you must follow the initial setup procedure below.
1) In visual studio C#, install the latest version of Protobuf and ClearScript addons.
2) Create a Unity 3D project named "AbyssUI", in the project root directory. Also, you need "AbyssUIBuild" folder in the project root directory, but this will be also created as default when you build the unity project.
3) In the Unity project, install Runtime OBJ Importer package from unity store (free), and also import Input System package.
4) Close the Unity project, and open powershell in project root directory. Run ./import_unity.ps1. This copies unity project codes from the abyss_unity folder to the AbyssUI unity project.
5) Run ./quick_rebuild.ps1 two times. The second run should succeed without any errors.

Now, we need to do an inconvence,
6) Create a temporary Visual Studio C# .NET framework 4.8 project in any directory (outside the project).
7) Install "Google.Protobuf" Nuget package and build solution.
8) Copy all the DLLs in the build folder into ./AbyssUI/Assets/Plugins. This should include Google.Protobuf.dll

9) Open the unity project. The unity editor should start withour an error (only warnings in the editor Debug Console).
10) Open Scenes/SampleScene, which will show an UI with two address bars.
11) Press "Play" button, and you should be able to write in the address bars.
12) Enter "https://minwoowebeng.github.io" in the top bar, which should load a world with a night city dummy skybox. Use WASDQZ for movement.
13) Leave play mode, and build unity project. Ensure you selected build directory to AbyssUIBuild.

Then, go to *How to Run* section.

**Warning: The AbyssUI unity project is ignored in the git repository**

To push changes in the AbyssUI unity project, you must manually run ./export_unity.ps1.
This copies codes from AbyssUI project to ./abyss_unity folder.
Edit ./export_unity.ps1 and ./import_unity.ps1 on disposal.

## Quick ReBuild

In powershell, run ./quick_rebuild.ps1 to rebuild the whole project except for the unity project, which has to be manually built within unity editor.
To partially build abyss_core or abyss_engine, you may run ./build_dll_debug.ps1 (in ./abyss_core), or ./build_debug.ps1 (in ./abyss_engine).

If you find any problem building, please let us know.
Thank you.

# Limitations

As NAT traversal itself is not our main research interest, we only tested our implementation without NAT, with each peer allocated a static IP.
It is highly likely that peers behind different NAT device will not be able to connect each other in current implemention.
NAT traversal between QUIC hosts is trivial; QUIC allows multiple connections between two hosts.
