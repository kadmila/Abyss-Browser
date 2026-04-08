using AbyssCLI.AmlResource;

namespace AbyssCLI.AML2;
internal sealed class Mesh : Transform
{
    private MeshResourceLink? meshResource;
    public Mesh(object? options, DocumentDependencies docDependencies) : base(ElementTag.Obj, options, docDependencies)
    {
        if (Attributes.TryGetValue("src", out string? mesh_src))
            Src = mesh_src;
    }

    // Rendering APIs
    public string? Src
    {
        get => meshResource?.Src;
        set
        {
            meshResource?.Dispose();
            if (value == null || value.Length == 0)
            {
                meshResource = null;
                return;
            }
            meshResource = new(docDependencies.Cache, value, ElementId);
        }
    }

    // resource link
    private sealed class MeshResourceLink(Cache.Cache shared_cache, string src, int element_id) : BetterResourceLink(shared_cache, src)
    {
        public override void Deploy()
        {
            if (Resource == null)
                return;
            if (!Resource.MIMEType.StartsWith("model") && Resource.MIMEType != "application/x-tgif")
            {
                Client.Client.RenderWriter.ConsolePrint("invalid content type for mesh: " + Resource.MIMEType);
                return;
            }
            Client.Client.RenderWriter.ElemAttachResource(element_id, Resource.ResourceID, ResourceRole.Mesh);
        }
        public override void Remove()
        {
            if (Resource == null)
                return;
            Client.Client.RenderWriter.ElemDetachResource(element_id, Resource.ResourceID);
        }
    }

    protected override void Dispose(bool is_root)
    {
        meshResource?.Dispose();
        base.Dispose(is_root);
    }
}
