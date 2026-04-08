using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2;
internal sealed class JavaScriptDispatcher : IDisposable
{
    private readonly V8ScriptEngine v8engine;
    public JavaScriptDispatcher(System.Collections.Concurrent.ConcurrentQueue<string> script_queue, V8RuntimeConstraints constraints, Document document)
    {
    
    }
    public void Dispose()
    {
        v8engine.Dispose();
        GC.SuppressFinalize(this);
    }
    ~JavaScriptDispatcher()
    {
        Client.Client.Cerr.WriteLine("JavaScriptDispatcher finalized without being disposed. This is a fatal bug.");
    }
}
