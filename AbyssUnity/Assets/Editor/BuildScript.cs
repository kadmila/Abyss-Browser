using UnityEditor;

public static class BuildScript
{
    public static void BuildWin64Mono()
    {
        BuildPlayerOptions options = new BuildPlayerOptions
        {
            scenes = new[]
            {
                "Assets/Scenes/Main.unity"
            },
            locationPathName = "../release/win-x64/Abyss.exe",
            target = BuildTarget.StandaloneWindows64,
            options = BuildOptions.None,
        };

        _ = BuildPipeline.BuildPlayer(options);
    }
}
