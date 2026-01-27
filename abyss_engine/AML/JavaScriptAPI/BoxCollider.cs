#nullable enable

namespace AbyssCLI.AML.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class BoxCollider : Element
{
    internal BoxCollider(JavaScriptDispatcher js_dispatcher, AML.Element origin) : base(js_dispatcher, origin) { }
    public float width
    {
        get => (_origin as AML.BoxCollider)!.width;
        set => (_origin as AML.BoxCollider)!.width = value;
    }
    public float height
    {
        get => (_origin as AML.BoxCollider)!.height;
        set => (_origin as AML.BoxCollider)!.height = value;
    }
    public float depth
    {
        get => (_origin as AML.BoxCollider)!.depth;
        set => (_origin as AML.BoxCollider)!.depth = value;
    }
}
