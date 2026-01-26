using AbyssCLI.HL;

namespace AbyssCLI.AML;
public class BoxCollider : Element
{
    private float _width = 1.0f;
    private float _height = 1.0f;
    private float _depth = 1.0f;
    public BoxCollider(Content origin, object? options) : base(origin, ElementTag.Bcol, options)
    {
        if (Attributes.TryGetValue("width", out string? width_str) && float.TryParse(width_str, out var width_par))
            width = width_par;

        if (Attributes.TryGetValue("height", out string? height_str) && float.TryParse(height_str, out var height_par))
            height = height_par;

        if (Attributes.TryGetValue("depth", out string? depth_str) && float.TryParse(depth_str, out var depth_par))
            depth = depth_par;
    }
    public float width
    {
        get => _width;
        set
        {
            Client.Client.RenderWriter.ElemSetValueF(ElementId, ValueRole.DimA, value);
            _width = value;
        }
    }
    public float height
    {
        get => _height;
        set
        {
            Client.Client.RenderWriter.ElemSetValueF(ElementId, ValueRole.DimB, value);
            _height = value;
        }
    }
    public float depth
    {
        get => _depth;
        set
        {
            Client.Client.RenderWriter.ElemSetValueF(ElementId, ValueRole.DimC, value);
            _depth = value;
        }
    }
}
