#nullable enable
using AbyssCLI.HL;

namespace AbyssCLI.AML;

#pragma warning disable IDE1006 //naming convension
public class PbrMaterial : Element
{
    private PbrTextureResourceLink? _albedo;
    private PbrTextureResourceLink? _normal;
    private PbrTextureResourceLink? _roughness;
    private PbrTextureResourceLink? _metalic;
    private PbrTextureResourceLink? _specular;
    private PbrTextureResourceLink? _opacity;
    private PbrTextureResourceLink? _emission;

    internal PbrMaterial(Content origin, object? options) : base(origin, ElementTag.Pbrm, options)
    {
        if (!Attributes.TryGetValue("albedo", out string? albedo_src))
            return;
        albedo = albedo_src;

        if (!Attributes.TryGetValue("normal", out string? normal_src))
            return;
        normal = normal_src;

        if (!Attributes.TryGetValue("roughness", out string? roughness_src))
            return;
        roughness = roughness_src;

        if (!Attributes.TryGetValue("metalic", out string? metalic_src))
            return;
        metalic = metalic_src;

        if (!Attributes.TryGetValue("specular", out string? specular_src))
            return;
        specular = specular_src;

        if (!Attributes.TryGetValue("opacity", out string? opacity_src))
            return;
        opacity = opacity_src;

        if (!Attributes.TryGetValue("emission", out string? emission_src))
            return;
        emission = emission_src;
    }

    public override bool IsParentAllowed(Element element) =>
        element is StaticMesh;
    public string? albedo
    {
        get => _albedo?.Src;
        set => Setter(ref _albedo, value, ResourceRole.Albedo);
    }
    public string? normal
    {
        get => _normal?.Src;
        set => Setter(ref _normal, value, ResourceRole.Normal);
    }
    public string? roughness
    {
        get => _roughness?.Src;
        set => Setter(ref _roughness, value, ResourceRole.Roughness);
    }
    public string? metalic
    {
        get => _metalic?.Src;
        set => Setter(ref _metalic, value, ResourceRole.Metalic);
    }
    public string? specular
    {
        get => _specular?.Src;
        set => Setter(ref _specular, value, ResourceRole.Specular);
    }
    public string? opacity
    {
        get => _opacity?.Src;
        set => Setter(ref _opacity, value, ResourceRole.Opacity);
    }
    public string? emission
    {
        get => _emission?.Src;
        set => Setter(ref _emission, value, ResourceRole.Emission);
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

        target = new PbrTextureResourceLink(Origin.Cache, value, ElementId, role);
    }

    private sealed class PbrTextureResourceLink(Cache.Cache shared_cache, string src, int element_id, ResourceRole role)
        : BetterResourceLink(shared_cache, src)
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
}
#pragma warning restore IDE1006 //naming convension

