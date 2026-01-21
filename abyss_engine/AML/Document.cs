using AbyssCLI.Cache;
using AbyssCLI.HL;
using Microsoft.ClearScript.V8;
using System.Text;

namespace AbyssCLI.AML;

/// <summary>
/// [MEMO]
/// AML head tag and its descendents are immutable.
/// </summary>
public class Document: IDisposable
{
    public ElementLifespanMan ElementLifespanManager;
    public readonly AmlMetadata Metadata;

    private readonly Content _origin;
    private int _ui_element_id = 0;
    private readonly Deallocator _script_dealloc_stack; // for fetched javascript source only.
    private readonly JavaScriptDispatcher _js_dispatcher;
    private bool IsUiInitialized => _ui_element_id != 0;

    // AML attributes
    private string _title;
    private class DocumentIconResourceLink(Cache.Cache shared_cache, int ui_element_id, string src) : BetterResourceLink(shared_cache, src)
    {
        public override void Deploy()
        {
            switch (Resource)
            {
                case StaticResource staticResource:
                    Client.Client.RenderWriter.ItemSetIcon(ui_element_id, staticResource.ResourceID);
                    break;
                case StaticSimpleResource staticSimpleResource:
                    Client.Client.RenderWriter.ItemSetIcon(ui_element_id, staticSimpleResource.ResourceID);
                    break;
                default:
                    Client.Client.RenderWriter.ConsolePrint("invalid content for icon");
                    break;
            }
        }
        public override void Remove() =>
            Client.Client.RenderWriter.ItemSetIcon(ui_element_id, 0);
    }
    private DocumentIconResourceLink? _iconSrc;

    // Body holds the root ElementId.
    public readonly Body Body;

    //document constructor must not allocate any resource that needs to be deallocated.
    public Document(Content origin, AmlMetadata metadata)
    {
        _origin = origin;
        Metadata = metadata;

        Body = new(origin);
        ElementLifespanManager = new(Body);

        _script_dealloc_stack = new();
        _js_dispatcher = new(new V8RuntimeConstraints(), this, new(ElementLifespanManager));
        _title = string.Empty;
    }
    /// <summary>
    /// Prepares DOM and UI
    /// </summary>
    public void Init()
    {
        Body.setTransformAsValues(Metadata.pos, Metadata.rot);
        Body.Init();

        if (Metadata.is_item)
            InitUI();
        Title = Metadata.title;
    }
    private void InitUI()
    {
        _ui_element_id = RenderID.ElementId;

        Client.Client.RenderWriter.CreateItem(
            _ui_element_id,
            Metadata.sharer_hash,
            Google.Protobuf.ByteString.CopyFrom(Metadata.uuid.ToByteArray())
        );
    }

    /// <summary>
    /// This starts JavaScriptDispatcher to push scripts
    /// If token cancels, no more scripts are added to engine, but engine keeps running.
    /// TODO: make JavaScriptDispatcher Disposal straightforward
    /// </summary>
    /// <param name="token"></param>
    public void StartJavaScript(CancellationToken token) =>
        _js_dispatcher.Start(token);

    public bool TryRunScript(string filename, string script) =>
        _js_dispatcher.TryEnqueue(filename, script);
    
    public bool TryFetchScript(string src)
    {
        var script_resource = _origin.Cache.GetReference(_origin.TranslateURL(src));
        _script_dealloc_stack.Add(new(script_resource));
        return _js_dispatcher.TryEnqueue(src, script_resource);
    }

    public void ScheduleOphanedElementCleanup() =>
        _js_dispatcher.TryEnqueue(string.Empty, new Action(ElementLifespanManager.CleanupOrphans));

    //features
    public string Title
    {
        get => _title;
        set
        {
            _title = value;
            Client.Client.RenderWriter.ItemSetTitle(_ui_element_id, value);
        }
    }
    public string? IconSrc
    {
        get => _iconSrc?.Src;
        set
        {
            if (value == null || value.Length == 0)
            {
                _iconSrc?.Dispose();
                _iconSrc = null;
                return;
            }
            if (_iconSrc != null)
            {
                _iconSrc.IsRemovalRequired = false;
                _iconSrc.Dispose();
            }
            _iconSrc = new(_origin.Cache, _ui_element_id, value);
        }
    }
    public Element CreateElement(string tag, object? options)
    {
        Element result = tag switch
        {
            "o" => new Transform(_origin, ElementTag.O, options),
            "obj" => new StaticMesh(_origin, options),
            "pbrm" => new PbrMaterial(_origin, options),
            "bcol" => new BoxCollider(_origin, options),
            _ => throw new ArgumentException("invalid tag")
        };
        ElementLifespanManager.Add(result);
        return result;
    }
    public Element? GetElementById(string id)
    {
        if (id == null)
            return null;
        if (id.Length == 0)
            return null;

        return Body.GetElementByIdHelper(id);
    }
    // TODO: define event callback API
    //public void setEventListener(string event_name, dynamic callback)
    //{
    //    //If same id is used, throw an exception.
    //    switch (event_name)
    //    {
    //    case "click":
    //        break;
    //    case "keydown":
    //        break;
    //    case "keyup":
    //        break;
    //    case "mousedown":
    //        break;
    //    case "mouseup":
    //        break;
    //    default:
    //        throw new Exception("unknown event: " + event_name);
    //    }
    //}
    //public void removeEventListener(string event_name)
    //{
    //    switch (event_name)
    //    {
    //    case "click":
    //        break;
    //    case "keydown":
    //        break;
    //    case "keyup":
    //        break;
    //    case "mousedown":
    //        break;
    //    case "mouseup":
    //        break;
    //    default:
    //        throw new Exception("unknown event: " + event_name);
    //    }
    //}

    public string GetStatistics(string prefix)
    {
        StringBuilder sb = new();
        _ = sb.AppendLine(prefix + "title: " + Title);
        _ = sb.AppendLine(prefix + "iconSrc: " + (IconSrc ?? "<none>"));
        _ = sb.AppendLine(prefix + "Metadata:");
        _ = sb.AppendLine(prefix + "  title: " + Metadata.title);
        _ = sb.AppendLine(prefix + "  pos: " + Metadata.pos.ToString());
        _ = sb.AppendLine(prefix + "  rot: " + Metadata.rot.ToString());
        _ = sb.AppendLine(prefix + "  is_item: " + Metadata.is_item.ToString());
        _ = sb.AppendLine(prefix + "  sharer_hash: " + Metadata.sharer_hash);
        _ = sb.AppendLine(prefix + "  uuid: " + Metadata.uuid.ToString());
        _ = sb.AppendLine(prefix + "ElementLifespanMan:");
        ElementLifespanManager.GetStatistics(sb);
        return sb.ToString();
    }

    public void Dispose()
    {
        Body.SetActive(false);
        if (IsUiInitialized)
            Client.Client.RenderWriter.ItemSetActive(_ui_element_id, false);

        // kill Javascript Engine, and wait for termination.
        _js_dispatcher.Dispose();
        // After this, Document is not mutated by JS.

        _iconSrc?.Dispose();
        _script_dealloc_stack.FreeAll();
        ElementLifespanManager.ClearAll();

        if (IsUiInitialized)
            Client.Client.RenderWriter.DeleteItem(_ui_element_id);

        GC.SuppressFinalize(this);
    }

    ~Document()
    {
        Client.Client.Cerr.WriteLine("Warning:::Document disposed by the garbage collector. It must be manually disposed. This is a bug.");
    }
}

