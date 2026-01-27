#nullable enable

namespace AbyssCLI.AML.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class PbrMaterial : Element
{
    internal PbrMaterial(JavaScriptDispatcher js_dispatcher, AML.Element origin) : base(js_dispatcher, origin) { }
    public string? albedo
    {
        get => (_origin as AML.PbrMaterial)!.albedo;
        set => (_origin as AML.PbrMaterial)!.albedo = value;
    }
    public string? normal
    {
        get => (_origin as AML.PbrMaterial)!.normal;
        set => (_origin as AML.PbrMaterial)!.normal = value;
    }
    public string? roughness
    {
        get => (_origin as AML.PbrMaterial)!.roughness;
        set => (_origin as AML.PbrMaterial)!.roughness = value;
    }
    public string? metalic
    {
        get => (_origin as AML.PbrMaterial)!.metalic;
        set => (_origin as AML.PbrMaterial)!.metalic = value;
    }
    public string? specular
    {
        get => (_origin as AML.PbrMaterial)!.specular;
        set => (_origin as AML.PbrMaterial)!.specular = value;
    }
    public string? opacity
    {
        get => (_origin as AML.PbrMaterial)!.opacity;
        set => (_origin as AML.PbrMaterial)!.opacity = value;
    }
    public string? emission
    {
        get => (_origin as AML.PbrMaterial)!.emission;
        set => (_origin as AML.PbrMaterial)!.emission = value;
    }
}
