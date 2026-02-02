# Abyss Browser
The Web Conf. 2026 Demo Track Artifact
Prototype Abyss Browser, along with a simple public peer registry.
<!-- See https://github.com/kadmila/Abyss-Browser/wiki for development guide, user guide, AML specification, and others. -->

# How to Run

Unzip release folder and double click on AbyssUI.exe to run.
On the first run, it creates an ed25519 private key (.pem), and abyst gateway configuration () json file.
The key is the user identity in Abyss.

To run multiple instances of the Abyss browser, copy the entire folder in different locations.
You MUST generate different keys for different instances. Otherwise, they will ignore each other.

# How to Build

This section explains how you can build & contribute to this project.

To build the binaries, you need
* go latest version windows/amd64
* visual studio 2022 with C# .NET framework 4.8 and Unity3D dev package.
* Unity 6.3 with Windows Build Support (IL2CPP)
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

1) Run ./project_init.ps1. This will take minutes. It should print three errors for missing directories.
2) Open Unity hub. Add > Add project from disk > select ./AbyssUnity folder.
3) Open the unity project. This will take a while.
4) When unity project opens without asking for safe mode, open "Main" from Scene.
5) In ./AbyssUnity/build.config, fill in "UnityExe" value with the path to your Unity 6.3 Unity.exe file.
This path must use "/" instead of "\", and must end with "Unity.exe".

Now, you may run debug build to update AbyssUnity project, or
run release build to produce release binary (/release folder).

## Debug Build

./build_debug.ps1

## Release Build

**Close Unity Editor before release build.**
./build_release.ps1
