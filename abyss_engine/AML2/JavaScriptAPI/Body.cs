using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;
public sealed class Body : Element
{
    internal Body(GraphUtil.L2TreeNodeRef origin, V8ScriptEngine target_engine) : base(origin, target_engine) { }
}
