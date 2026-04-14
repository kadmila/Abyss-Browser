using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class Element
{
    internal readonly GraphUtil.L2TreeNodeRef _origin;
    private readonly V8ScriptEngine _v8engine;
    internal Element(GraphUtil.L2TreeNodeRef origin, V8ScriptEngine target_engine)
    {
        _origin = origin;
        _v8engine = target_engine;
    }
    public void __dispose()
    {
        _origin.Dispose();
    }
}
