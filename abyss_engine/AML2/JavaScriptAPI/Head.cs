using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;
public sealed class Head : Element
{
    internal Head(GraphUtil.L2TreeNodeRef origin, V8ScriptEngine target_engine) : base(origin, target_engine) { }
}
