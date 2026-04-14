using Microsoft.ClearScript;
using Microsoft.ClearScript.V8;
using System.Collections.Concurrent;

namespace AbyssCLI.AML2;
internal sealed class JavaScriptDispatcher : IDisposable
{
    private readonly V8ScriptEngine v8engine;
    private readonly BlockingCollection<(string, string)> scriptQueue;

    // JS standard library utilities
    private readonly JavaScriptAPI.Timer timer;

    public JavaScriptDispatcher(BlockingCollection<(string, string)> script_queue, V8RuntimeConstraints constraints, Document document)
    {
        v8engine = new V8ScriptEngine(constraints, V8ScriptEngineFlags.DisableGlobalMembers);
        scriptQueue = script_queue;
        timer = new();

        // __aefr: AML Element Finalization Registry
        // __aefrat: AEFR attach
        v8engine.AddHostObject("document", new JavaScriptAPI.Document(document, v8engine));
        v8engine.Execute(@"
const version = '" + Tool.ExternData.BuildTime + @"';
const __aefr = new FinalizationRegistry(f=>f());
function __aefrat(e) {
    __aefr.register(e, e.__dispose);
    return e;
}
class DOMException extends Error {
    constructor(message) {
        super(message);
        this.name = ""DOMException"";
    }
}
class HierarchyRequestException extends Error {
    constructor(message) {
        super(message);
        this.name = ""HierarchyRequestException"";
    }
}
class NotSupportedException extends Error {
    constructor(message) {
        super(message);
        this.name = ""NotSupportedException"";
    }
}
");
    }
    public void Run(CancellationToken token)
    {
        while (true)
        {
            try
            {
                var (filename, js_code) = scriptQueue.Take(token);
                v8engine.Execute(new DocumentInfo(filename), js_code);
            }
            catch (ScriptEngineException ex)
            {
                Client.Client.Cerr.WriteLine($"javascript error: {ex.ErrorDetails}");
            }
            catch (OperationCanceledException) //token cancellation
            {
                return;
            }
            catch (Exception ex)
            {
                Client.Client.Cerr.WriteLine($"fatal::: {ex}");
            }
        }
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
