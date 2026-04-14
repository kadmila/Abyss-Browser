using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class Document
{
    private readonly AML2.Document _origin;
    private readonly V8ScriptEngine _v8engine;
    internal Document(AML2.Document origin, V8ScriptEngine target_engine)
    {
        _origin = origin;
        _v8engine = target_engine;
    }
    public dynamic? head
    {
        get
        {
            var native_head = _origin.Head;
            if (native_head == null)
                return null;

            var jshandle = new Head(native_head!, _v8engine);
            return _v8engine.Script.__aefrat(jshandle);
        }
        set
        {
            _origin.Head = value?._origin;
        }
    }
    public dynamic? body
    {
        get
        {
            var native_head = _origin.Head;
            if (native_head == null)
                return null;

            var jshandle = new Body(native_head!, _v8engine);
            return _v8engine.Script.__aefrat(jshandle);
        }
        set
        {
            _origin.Head = value?._origin;
        }
    }
}
