using AbyssCLI.AmlResource;
using AbyssCLI.Cache;

namespace AbyssCLI.AML2;
internal class Document : IDisposable // Document is not an Element.
{
    private readonly DocumentDependencies docDependencies;
    private readonly int uiElementID = 0;
    private DocumentIconResourceLink? iconResource;

    public readonly GraphUtil.L2Forest DOM;
    public readonly GraphUtil.L2TreeNodeRef Root; // This refernce must stay valid;
    public GraphUtil.L2TreeNodeRef? Head {get; private set;}
    public GraphUtil.L2TreeNodeRef? Body {get; private set;}
    public Document(DocumentDependencies documentDI)
    {
        this.docDependencies = documentDI;
        DOM = new();
        Root = DOM.Insert(new Transform(ElementTag.O, null, documentDI));
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
