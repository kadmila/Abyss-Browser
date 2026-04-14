using AbyssCLI.AmlResource;
using AbyssCLI.Cache;
using AbyssCLI.GraphUtil;

namespace AbyssCLI.AML2;
internal class Document : IDisposable // Document is not an Element.
{
    private readonly DocumentDependencies docDependencies;
    private readonly AmlMetadata metadata;
    private readonly int uiElementID = 0;
    private DocumentIconResourceLink? iconResource;

    public readonly GraphUtil.L2Forest DOM;
    public readonly GraphUtil.L2TreeNodeRef Root; // <aml>. This refernce must stay valid;

    public Document(DocumentDependencies docDependencies, AmlMetadata metadata)
    {
        this.docDependencies = docDependencies;
        this.metadata = metadata;
        DOM = new();
        Root = DOM.Insert(new AML(null, docDependencies));
    }

    // Rendering APIs
    public string? Icon
    {
        get => iconResource?.Src;
        set
        {
            if (value == null || value.Length == 0)
            {
                iconResource?.Dispose();
                iconResource = null;
                return;
            }

            if (iconResource != null)
            {
                iconResource.IsRemovalRequired = false;
                iconResource.Dispose();
            }

            iconResource = new(docDependencies.Cache, uiElementID, value);
        }
    }

    // JavaScript APIs
    public L2TreeNodeRef? Head
    {
        get
        {
            var result = Root.FindChild(
                node => (node as Element)!.Tag == ElementTag.Head
            );
            return result;
        }
        set
        {
            using var old_head = Root.FindChild(
                node => (node as Element)!.Tag == ElementTag.Head
            );
            old_head?.Isolate();

            if (value != null)
                Root.AddChild(value);
        }
    }
    public L2TreeNodeRef? Body
    {
        get
        {
            var result = Root.FindChild(
                node => (node as Element)!.Tag == ElementTag.Body
            );
            return result;
        }
        set
        {
            using var old_body = Root.FindChild(
                node => (node as Element)!.Tag == ElementTag.Body
            );
            old_body?.Isolate();

            if (value != null)
                Root.AddChild(value);
        }
    }

    // Unsafe internal APIs
    public Element Unsafe_CreateElement(string tag, object? options) =>
        tag switch
        {
            "head" => new Head(options, docDependencies),
            //"script" =>
            //"link" =>
            //"meta" =>
            "body" => new Body(options, docDependencies),
            "o" => new Transform(ElementTag.O, options, docDependencies),
            "obj" => new Mesh(options, docDependencies),
            "pbrm" => new PbrMaterial(options, docDependencies),
            _ => new InvalidElement(tag, options, docDependencies)
        };

    // resource link
    private sealed class DocumentIconResourceLink(Cache.Cache shared_cache, int ui_element_id, string src) : BetterResourceLink(shared_cache, src)
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

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
    ~Document()
    {
        Client.Client.Cerr.WriteLine("AML Document finalized without being disposed. This is a bug.");
    }
}
