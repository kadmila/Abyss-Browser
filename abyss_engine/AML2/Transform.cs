namespace AbyssCLI.AML2;
internal class Transform : Element
{
    // AML attributes
    private Vector3 Position;
    private Quaternion Rotation;
    public Transform(ElementTag tag, object? options, DocumentDependencies docDependencies) : base(tag, options, docDependencies)
    {
        //apply attributes
        Position = Attributes.TryGetValue("pos", out string? pos) ? new(pos) : new();
        Rotation = Attributes.TryGetValue("rot", out string? rot) ? new(rot) : new();
        Client.Client.RenderWriter.ElemSetTransform(
            ElementId,
            Position.MarshalForABI(),
            Rotation.MarshalForABI()
        );
    }

    // Rendering APIs
    public string Pos {
        get
        {
            return Position.ToString();
        }
        set
        {
            Position = new(value);
            Client.Client.RenderWriter.ElemSetTransform(
                ElementId,
                Position.MarshalForABI(),
                Rotation.MarshalForABI()
            );
        }
    }
    public string Rot {
        get
        {
            return Rotation.ToString();
        }
        set
        {
            Rotation = new(value);
            Client.Client.RenderWriter.ElemSetTransform(
                ElementId,
                Position.MarshalForABI(),
                Rotation.MarshalForABI()
            );
        }
    }
}
