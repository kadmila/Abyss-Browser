using AbyssCLI.AmlResource;

namespace AbyssCLI.AML2;
internal sealed class PbrMaterial : Element
{
    private PbrTextureResourceLink? albedo;
    private PbrTextureResourceLink? normal;
    private PbrTextureResourceLink? roughness;
    private PbrTextureResourceLink? metalic;
    private PbrTextureResourceLink? specular;
    private PbrTextureResourceLink? opacity;
    private PbrTextureResourceLink? emission;
    public PbrMaterial(object? options, DocumentDependencies docDependencies) : base(ElementTag.Pbrm, options, docDependencies)
    {
        if (Attributes.TryGetValue("albedo", out string? albedo_src))
            Albedo = albedo_src;

        if (Attributes.TryGetValue("normal", out string? normal_src))
            Normal = normal_src;

        if (Attributes.TryGetValue("roughness", out string? roughness_src))
            Roughness = roughness_src;

        if (Attributes.TryGetValue("metalic", out string? metalic_src))
            Metalic = metalic_src;

        if (Attributes.TryGetValue("specular", out string? specular_src))
            Specular = specular_src;

        if (Attributes.TryGetValue("opacity", out string? opacity_src))
            Opacity = opacity_src;

        if (Attributes.TryGetValue("emission", out string? emission_src))
            Emission = emission_src;
    }

    // Rendering APIs
    public string? Albedo
    {
        get => albedo?.Src;
        set => Setter(ref albedo, value, ResourceRole.Albedo);
    }
    public string? Normal
    {
        get => normal?.Src;
        set => Setter(ref normal, value, ResourceRole.Normal);
    }
    public string? Roughness
    {
        get => roughness?.Src;
        set => Setter(ref roughness, value, ResourceRole.Roughness);
    }
    public string? Metalic
    {
        get => metalic?.Src;
        set => Setter(ref metalic, value, ResourceRole.Metalic);
    }
    public string? Specular
    {
        get => specular?.Src;
        set => Setter(ref specular, value, ResourceRole.Specular);
    }
    public string? Opacity
    {
        get => opacity?.Src;
        set => Setter(ref opacity, value, ResourceRole.Opacity);
    }
    public string? Emission
    {
        get => emission?.Src;
        set => Setter(ref emission, value, ResourceRole.Emission);
    }
    private void Setter(ref PbrTextureResourceLink? target, string? value, ResourceRole role)
    {
        if (value == null || value.Length == 0)
        {
            target?.Dispose();
            target = null;
            return;
        }

        if (target != null)
        {
            target.IsRemovalRequired = false;
            target.Dispose();
        }

        target = new PbrTextureResourceLink(docDependencies.Cache, value, ElementId, role);
    }

    // resource link
    private sealed class PbrTextureResourceLink(Cache.Cache shared_cache, string src, int element_id, ResourceRole role) : BetterResourceLink(shared_cache, src)
    {
        public override void Deploy()
        {
            if (Resource == null)
                return;
            if (!Resource.MIMEType.StartsWith("image"))
            {
                Client.Client.RenderWriter.ConsolePrint("non-image resources cannot be used as a pbr texture");
                return;
            }
            Client.Client.RenderWriter.ElemAttachResource(element_id, Resource.ResourceID, role);
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
        albedo?.Dispose();
        normal?.Dispose();
        roughness?.Dispose();
        metalic?.Dispose();
        specular?.Dispose();
        opacity?.Dispose();
        emission?.Dispose();
        base.Dispose(is_root);
    }
}
