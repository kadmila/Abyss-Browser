Remove-Item -Path .\abyss_unity\unity_source -Recurse -Force

# create directories for Assets
New-Item -Path .\abyss_unity\unity_source\Assets\AbyssUI -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\baseMaterial -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\DOM -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\EngineCom -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\Executor -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\GlobalDependency -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\Host -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\images -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\Materials -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\Scenes -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\Assets\test -ItemType Directory
New-Item -Path ".\abyss_unity\unity_source\Assets\UI Toolkit" -ItemType Directory
# Copy directories in Assets
Copy-Item -Path .\AbyssUI\Assets\AbyssUI\* -Destination .\abyss_unity\unity_source\Assets\AbyssUI\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\baseMaterial\* -Destination .\abyss_unity\unity_source\Assets\baseMaterial\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\DOM\* -Destination .\abyss_unity\unity_source\Assets\DOM\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\EngineCom\* -Destination .\abyss_unity\unity_source\Assets\EngineCom\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\Executor\* -Destination .\abyss_unity\unity_source\Assets\Executor\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\GlobalDependency\* -Destination .\abyss_unity\unity_source\Assets\GlobalDependency\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\Host\* -Destination .\abyss_unity\unity_source\Assets\Host\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\images\* -Destination .\abyss_unity\unity_source\Assets\images\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\Materials -Destination .\abyss_unity\unity_source\Assets\Materials\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\Scenes\* -Destination .\abyss_unity\unity_source\Assets\Scenes\ -Recurse -Force
Copy-Item -Path .\AbyssUI\Assets\test\* -Destination .\abyss_unity\unity_source\Assets\test\ -Recurse -Force
Copy-Item -Path ".\AbyssUI\Assets\UI Toolkit\*" -Destination ".\abyss_unity\unity_source\Assets\UI Toolkit\" -Recurse -Force
#meta
Copy-Item -Path .\AbyssUI\Assets\AbyssUI.meta -Destination .\abyss_unity\unity_source\Assets\AbyssUI.meta -Force
Copy-Item -Path .\AbyssUI\Assets\baseMaterial.meta -Destination .\abyss_unity\unity_source\Assets\baseMaterial.meta -Force
Copy-Item -Path .\AbyssUI\Assets\DOM.meta -Destination .\abyss_unity\unity_source\Assets\DOM.meta -Force
Copy-Item -Path .\AbyssUI\Assets\EngineCom.meta -Destination .\abyss_unity\unity_source\Assets\EngineCom.meta -Force
Copy-Item -Path .\AbyssUI\Assets\Executor.meta -Destination .\abyss_unity\unity_source\Assets\Executor.meta -Force
Copy-Item -Path .\AbyssUI\Assets\GlobalDependency.meta -Destination .\abyss_unity\unity_source\Assets\GlobalDependency.meta -Force
Copy-Item -Path .\AbyssUI\Assets\Host.meta -Destination .\abyss_unity\unity_source\Assets\Host.meta -Force
Copy-Item -Path .\AbyssUI\Assets\images.meta -Destination .\abyss_unity\unity_source\Assets\images.meta -Force
Copy-Item -Path .\AbyssUI\Assets\Materials.meta -Destination .\abyss_unity\unity_source\Assets\Materials.meta -Force
Copy-Item -Path .\AbyssUI\Assets\Scenes.meta -Destination .\abyss_unity\unity_source\Assets\Scenes.meta -Force
Copy-Item -Path .\AbyssUI\Assets\test.meta -Destination .\abyss_unity\unity_source\Assets\test.meta -Force
Copy-Item -Path ".\AbyssUI\Assets\UI Toolkit.meta" -Destination ".\abyss_unity\unity_source\Assets\UI Toolkit.meta" -Force
# Copy files in Assets
Copy-Item -Path .\AbyssUI\Assets\AbyssUI_v0.9.prefab -Destination .\abyss_unity\unity_source\Assets\AbyssUI_v0.9.prefab -Recurse -Force
#meta
Copy-Item -Path .\AbyssUI\Assets\AbyssUI_v0.9.prefab.meta -Destination .\abyss_unity\unity_source\Assets\AbyssUI_v0.9.prefab.meta -Recurse -Force

# create directories for other folders in AbyssUI
New-Item -Path .\abyss_unity\unity_source\ProjectSettings -ItemType Directory
New-Item -Path .\abyss_unity\unity_source\UserSettings -ItemType Directory
# Copy Other folders in AbyssUI
Copy-Item -Path .\AbyssUI\ProjectSettings\* -Destination .\abyss_unity\unity_source\ProjectSettings\ -Recurse -Force
Copy-Item -Path .\AbyssUI\UserSettings\* -Destination .\abyss_unity\unity_source\UserSettings\ -Recurse -Force
# Copy Other files in AbyssUI
Copy-Item -Path .\AbyssUI\AbyssUI.sln -Destination .\abyss_unity\unity_source\AbyssUI.sln -Force
Copy-Item -Path .\AbyssUI\app.config -Destination .\abyss_unity\unity_source\app.config -Force
Copy-Item -Path .\AbyssUI\Assembly-CSharp-Editor.csproj -Destination .\abyss_unity\unity_source\Assembly-CSharp-Editor.csproj -Force
Copy-Item -Path .\AbyssUI\Assembly-CSharp.csproj -Destination .\abyss_unity\unity_source\Assembly-CSharp.csproj -Force
Copy-Item -Path .\AbyssUI\build_release.ps1 -Destination .\abyss_unity\unity_source\build_release.ps1 -Force
Copy-Item -Path .\AbyssUI\packages.config -Destination .\abyss_unity\unity_source\packages.config -Force
