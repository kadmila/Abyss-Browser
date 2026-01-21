#nullable enable
using AbyssCLI.HL;

namespace AbyssCLI.AML;

#pragma warning disable IDE1006 //naming convension
public class Transform : Element
{
    public (Vector3, Quaternion) _transform = (new(), new()); //TODO: dynamic transform
    public Transform(Content origin, ElementTag tag, object? options) : base(origin, tag, options)
    {
        //apply attributes
        foreach (KeyValuePair<string, string> entry in Attributes)
        {
            switch (entry.Key)
            {
            case "pos":
                pos = entry.Value;
                break;
            case "rot":
                rot = entry.Value;
                break;
            default:
                break;
            }
        }
    }
    public override bool IsParentAllowed(Element element) => element is Transform;

    //Javascript APIs
    public string pos
    {
        set
        {
            _transform.Item1 = new(value);
            Client.Client.RenderWriter.ElemSetTransform(
                ElementId,
                _transform.Item1.MarshalForABI(),
                _transform.Item2.MarshalForABI()
            );
        }
        get
        {
            return _transform switch
            {
                (Vector3 position, Quaternion _) => position.ToString(),
                _ => "undefined",
            };
        }
    }
    public string rot
    {
        set
        {
            _transform.Item2 = new(value);
            Client.Client.RenderWriter.ElemSetTransform(
                ElementId,
                _transform.Item1.MarshalForABI(),
                _transform.Item2.MarshalForABI()
            );
        }
        get
        {
            return _transform switch
            {
                (Vector3 _, Quaternion rotation) => rotation.ToString(),
                _ => "undefined",
            };
        }
    }
    public void setTransformAsValues(Vector3 pos, Quaternion rot)
    {
        _transform = (pos, rot);
        Client.Client.RenderWriter.ElemSetTransform(ElementId, pos.MarshalForABI(), rot.MarshalForABI());
    }
}
#pragma warning restore IDE1006 //naming convension

