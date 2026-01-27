#nullable enable
#pragma warning disable IDE1006 //naming convension
namespace AbyssCLI.AML.JavaScriptAPI;

public class Transform : Element
{
    internal Transform(JavaScriptDispatcher js_dispatcher, AML.Element origin) : base(js_dispatcher, origin) { }
    public string pos
    {
        get => (_origin as AML.Transform)!.pos;
        set => (_origin as AML.Transform)!.pos = value;
    }
    public string rot
    {
        get => (_origin as AML.Transform)!.rot;
        set => (_origin as AML.Transform)!.rot = value;
    }
}
