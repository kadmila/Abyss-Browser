using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;
public class Transform : Element
{
    public Transform(GraphUtil.L2TreeNodeRef origin, V8ScriptEngine target_engine) : base(origin, target_engine) { }
}
