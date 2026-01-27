#nullable enable

namespace AbyssCLI.AML.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class StaticMesh : Transform
{
    internal StaticMesh(JavaScriptDispatcher js_dispatcher, AML.Element origin) : base(js_dispatcher, origin) { }
    public string? src
    {
        get => (_origin as AML.StaticMesh)!.src;
        set => (_origin as AML.StaticMesh)!.src = value;
    }
}
