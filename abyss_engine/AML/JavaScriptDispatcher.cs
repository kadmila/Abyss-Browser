using AbyssCLI.Cache;
using AbyssCLI.Tool;
using Microsoft.ClearScript;
using Microsoft.ClearScript.JavaScript;
using Microsoft.ClearScript.V8;
using System.Collections.Concurrent;

namespace AbyssCLI.AML;

#pragma warning disable IDE1006 //naming convension
public class JavaScriptGcCallback(ElementLifespanMan elem_lifespan_man)
{
    public void on_gc(int element_id)
    {
        Element elem = elem_lifespan_man.Find(element_id);
        elem.RefCount--;
    }
}
#pragma warning restore IDE1006 //naming convension

public class JavaScriptDispatcher : IDisposable
{
    private readonly V8ScriptEngine _engine;
    private readonly BlockingCollection<(string, object)> _queue = []; // by default, 100 scripts can be queued at once
    private readonly Thread _thread;

    private readonly JavaScriptAPI.Timer _timer = new();

    public JavaScriptDispatcher(V8RuntimeConstraints constraints, Document document, JavaScriptGcCallback gc_callback)
    {
        _engine = new V8ScriptEngine(constraints, V8ScriptEngineFlags.DisableGlobalMembers);

        _engine.AddHostType("Vector3", typeof(Vector3));
        _engine.AddHostType("Quaternion", typeof(Quaternion));
        _engine.AddHostType("Event", typeof(AMLEvent.AmlEvent));
        _engine.AddHostType("KeyboardEvent", typeof(AMLEvent.KeyboardEvent));

        _engine.AddHostObject("document", new JavaScriptAPI.Document(this, document));
        _engine.AddHostObject("console", new JavaScriptAPI.Console());
        _engine.AddHostObject("setTimeout", new Action<ScriptObject, int>(_timer.SetTimeout));
        _engine.AddHostObject("__fetch_api", new JavaScriptAPI.FetchApi(_engine));
        _engine.AddHostObject("sleep", new Func<int, object>(t=>JavaScriptExtensions.ToPromise(Task.Delay(t))));
        _engine.AddHostObject("host", new JavaScriptAPI.Host());

        _engine.AddHostObject("elem_gc_callback", gc_callback);

        _engine.Execute(@"
const version = '" + Tool.ExternData.BuildTime + @"';

const __aml_elem_finreg = new FinalizationRegistry(heldValue => elem_gc_callback.on_gc(heldValue));
function __aml_elem_dtor_reg(target, heldValue) {
    __aml_elem_finreg.register(target, heldValue);
    return target;
}

const fetch = (a, b) => __fetch_api.FetchAsync(a, b)
"
        );

        _thread = new Thread(new ParameterizedThreadStart(Run!));
    }
    public bool TryEnqueue(string filename, object entry) =>
        _queue.TryAdd((filename, entry));
    public void Start(CancellationToken token) =>
        _thread.Start(token);
    private async void Run(object token_)
    {
        var token = (CancellationToken)token_;
        while (!token.IsCancellationRequested)
        {
            try
            {
                await RunOneScript(token);
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
    private async Task RunOneScript(CancellationToken token)
    {
        switch (_queue.Take(token))
        {
        case (string text_title, string script_text):
        {
            //Client.Client.RenderWriter.ConsolePrint("JsDispatcher: running " + (text_title.Length == 0 ? "<script>" : text_title));
            _engine.Execute(new Microsoft.ClearScript.DocumentInfo("<script>"), script_text);

            ///debug - GC
            _engine.CollectGarbage(true);
            GC.Collect();
            GC.WaitForPendingFinalizers();
            _engine.Execute("void 0");
            //Client.Client.RenderWriter.ConsolePrint("JsDispatcher: finished " + (text_title.Length == 0 ? "<script>" : text_title));
            break;
        }
        case (string file_name, TaskCompletionReference<CachedResource> script_ref):
        {
            //Client.Client.RenderWriter.ConsolePrint("JsDispatcher: loading " + file_name);
            CachedResource script_resource = await script_ref.Task.WaitAsync(token);
            //Client.Client.RenderWriter.ConsolePrint("JsDispatcher: running " + file_name);
            if (script_resource is not Cache.Text)
            {
                Client.Client.Cerr.WriteLine(script_resource.MIMEType);
                Client.Client.Cerr.WriteLine("invalid javascript resource");
                return;
            }
            if (script_resource.MIMEType != "text/javascript")
            {
                Client.Client.Cerr.WriteLine("javascript MIME mismatch: " + script_resource.MIMEType);
                return;
            }
            string remote_script_text = await (script_resource as Cache.Text)!.ReadAsync(token);
            _engine.Execute(new Microsoft.ClearScript.DocumentInfo(file_name), remote_script_text);
            //Client.Client.RenderWriter.ConsolePrint("JsDispatcher: finished " + file_name);
            break;
        }
        case (_, Action action):
            action();
            break;
        default:
            throw new InvalidOperationException("Unsupported script type (fatal internal error)");
        }
    }
    //for JavaScript API
    public object MarshalElement(AML.Element element)
    {
        //Client.Client.RenderWriter.ConsolePrint("++JsEngine claims an element handle: " + element.ElementId);
        element.RefCount++;
        JavaScriptAPI.Element result = element switch
        {
            AML.Body body => new JavaScriptAPI.Body(this, body),
            AML.StaticMesh static_mesh => new JavaScriptAPI.StaticMesh(this, static_mesh),
            AML.PbrMaterial pbr_material => new JavaScriptAPI.PbrMaterial(this, pbr_material),
            AML.Transform transform => new JavaScriptAPI.Transform(this, transform),
            AML.BoxCollider box_collider => new JavaScriptAPI.BoxCollider(this, box_collider),
            _ => throw new NotImplementedException()
        };
        return _engine.Script.__aml_elem_dtor_reg(result, element.ElementId);
    }
    public object MarshalElementArray(List<AML.Element> elements)
    {
        dynamic jsArray = _engine.Evaluate("[]");
        foreach (var v in elements)
            jsArray.push(v);
        return jsArray;
    }

    public void Dispose()
    {
        _timer.Interrupt();
        _engine.Interrupt();

        _timer.Join();
        if (_thread.IsAlive)
            _thread.Join();
        _queue.Dispose();
        _engine.Dispose();

        GC.SuppressFinalize(this);
    }

    ~JavaScriptDispatcher()
    {
        Client.Client.Cerr.WriteLine("Fatal:::JavaScriptDispatcher destroyed by the garbage collecter. It should be manually disposed. This is a bug");
        Dispose();
    }
}
