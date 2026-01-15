using AbyssCLI.Cache;
using AbyssCLI.HL;
using Microsoft.ClearScript.V8;
using System.Text;

namespace AbyssCLI.AML;

/// <summary>
/// [MEMO]
/// When disposing elements in _detached_elements,
/// it should be noted that some of them may have Rc.DoRefExist == false, but
/// actually it may be before the initial reference creation.
/// </summary>
public class Document
{
    public ElementLifespanMan ElementLifespanManager;
    public readonly AmlMetadata Metadata;

    private readonly ContentB _origin;
    private int _ui_element_id = 0;
    private readonly Deallocator _dealloc_stack;
    private readonly JavaScriptDispatcher _js_dispatcher;
    private bool IsUiInitialized => _ui_element_id != 0;

    //document constructor must not allocate any resource that needs to be deallocated.
    public Document(ContentB origin, AmlMetadata metadata)
    {
        _origin = origin;
        Metadata = metadata;

        head = new();
        body = new(origin);
        ElementLifespanManager = new(body);

        _dealloc_stack = new();
        _js_dispatcher = new(new V8RuntimeConstraints(), this, new(ElementLifespanManager));
        _title = string.Empty;
    }
    /// <summary>
    /// Prepares DOM and UI
    /// </summary>
    public void Init()
    {
        body.setTransformAsValues(Metadata.pos, Metadata.rot);
        body.Init();

        if (Metadata.is_item)
            InitUI();
        title = Metadata.title;
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
    /// Add an entry to the deallocation stack. 
    /// warning: _dealloc_stack is not thread safe.
    /// All calls of this must be called synchronously by architecture.
    /// </summary>
    /// <param name="entry"></param>
    public void AddToDeallocStack(DeallocEntry entry) =>
        _dealloc_stack.Add(entry);

    /// <summary>
    /// This starts JavaScriptDispatcher to push scripts
    /// If token cancels, no more scripts are added to engine, but engine keeps running.
    /// TODO: make JavaScriptDispatcher Disposal straightforward
    /// </summary>
    /// <param name="token"></param>
    public void StartJavaScript(CancellationToken token) =>
        _js_dispatcher.Start(token);

    /// <summary>
    /// Try to enqueue a javascript script to be executed.
    /// This is thread safe, but fails when the queue is full.
    /// </summary>
    /// <param name="filename"></param>
    /// <param name="script"></param>
    /// <returns></returns>
    public bool TryEnqueueJavaScript(string filename, object script) =>
        _js_dispatcher.TryEnqueue(filename, script);

    public void ScheduleOphanedElementCleanup() =>
        _js_dispatcher.TryEnqueue(string.Empty, new Action(ElementLifespanManager.CleanupOrphans));

    /// <summary>
    /// Interrupt javascript execution and deactivates document. 
    /// This must be called only after token cancellation.
    /// </summary>
    public void Interrupt()
    {
        body.setActive(false);
        if (IsUiInitialized)
            Client.Client.RenderWriter.ItemSetActive(_ui_element_id, false);
        _js_dispatcher.Interrupt();
    }

    /// <summary>
    /// Waits for javascript dispatcher to finish execution and deallocates all resources.
    /// Calling this is mendatory.
    /// </summary>
    public void Join()
    {
        _js_dispatcher.Join();
        _iconSrc?.Dispose();
        _dealloc_stack.FreeAll();
        ElementLifespanManager.ClearAll();
        if (IsUiInitialized)
            Client.Client.RenderWriter.DeleteItem(_ui_element_id);
    }

    // inner attributes
    private string _title;
    private DocumentIconResourceLink? _iconSrc;

    public readonly Head head;
    public readonly Body body;

    //features
    public string title
    {
        get => _title;
        set
        {
            _title = value;
            Client.Client.RenderWriter.ItemSetTitle(_ui_element_id, value);
        }
    }
    public string? iconSrc
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
    public Element createElement(string tag, object? options)
    {
        Element result = tag switch
        {
            "o" => new Transform(_origin, tag, options),
            "obj" => new StaticMesh(_origin, options),
            "pbrm" => new PbrMaterial(_origin, options),
            "bcol" => new BoxCollider(_origin, options),
            _ => throw new ArgumentException("invalid tag")
        };
        ElementLifespanManager.Add(result);
        return result;
    }
    public Element? getElementById(string id)
    {
        if (id == null)
            return null;
        if (id.Length == 0)
            return null;

        return body.getElementByIdHelper(id);
    }
    public void setEventListener(string event_name, dynamic callback)
    {
        //If same id is used, throw an exception.
        switch (event_name)
        {
        case "click":
            break;
        case "keydown":
            break;
        case "keyup":
            break;
        case "mousedown":
            break;
        case "mouseup":
            break;
        default:
            throw new Exception("unknown event: " + event_name);
        }
    }
    public void removeEventListener(string event_name)
    {
        switch (event_name)
        {
        case "click":
            break;
        case "keydown":
            break;
        case "keyup":
            break;
        case "mousedown":
            break;
        case "mouseup":
            break;
        default:
            throw new Exception("unknown event: " + event_name);
        }
    }

    public string GetStatistics(string prefix)
    {
        StringBuilder sb = new();
        _ = sb.AppendLine(prefix + "title: " + title);
        _ = sb.AppendLine(prefix + "iconSrc: " + (iconSrc ?? "<none>"));
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
}
#pragma warning restore IDE1006 //naming convension

