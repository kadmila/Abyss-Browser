namespace AbyssCLI.AML2;

// These types are used in the AML document.
// They are exposed to JS; Compatibility is mendatory.
public class Vector3
{
    private System.Numerics.Vector3 _inner;
    public Vector3()
    {
        _inner = new();
    }
    public Vector3(object x)
    {
        object[] parsed_x = TypeConv.ToArray(x, 3);
        _inner = new System.Numerics.Vector3(
            TypeConv.ToFloat(parsed_x[0]),
            TypeConv.ToFloat(parsed_x[1]),
            TypeConv.ToFloat(parsed_x[2])
        );
    }
    public Vector3(object x, object y, object z)
    {
        _inner = new System.Numerics.Vector3(
            TypeConv.ToFloat(x),
            TypeConv.ToFloat(y),
            TypeConv.ToFloat(z)
        );
    }
    internal Vector3(System.Numerics.Vector3 inner)
    {
        _inner = inner;
    }
    public override string ToString() =>
        _inner.ToString();

    internal System.Numerics.Vector3 Native => _inner;
    internal ABI.Vec3 MarshalForABI()
    {
        return new ABI.Vec3
        {
            X = _inner.X,
            Y = _inner.Y,
            Z = _inner.Z
        };
    }
}

public class Quaternion
{
    private System.Numerics.Quaternion _inner;
    public Quaternion()
    {
        _inner = new()
        {
            W = 1
        };
    }
    public Quaternion(object x)
    {
        object[] parsed_x = TypeConv.ToArray(x, 4);
        _inner = new System.Numerics.Quaternion(
            TypeConv.ToFloat(parsed_x[0]),
            TypeConv.ToFloat(parsed_x[1]),
            TypeConv.ToFloat(parsed_x[2]),
            TypeConv.ToFloat(parsed_x[3])
        );
    }
    public Quaternion(object x, object y, object z, object w)
    {
        _inner = new System.Numerics.Quaternion(
            TypeConv.ToFloat(x),
            TypeConv.ToFloat(y),
            TypeConv.ToFloat(z),
            TypeConv.ToFloat(w)
        );
    }
    internal Quaternion(System.Numerics.Quaternion inner)
    {
        _inner = inner;
    }
    public override string ToString() =>
        _inner.ToString();

    internal System.Numerics.Quaternion Native => _inner;
    internal ABI.Vec4 MarshalForABI()
    {
        return new ABI.Vec4
        {
            X = _inner.X,
            Y = _inner.Y,
            Z = _inner.Z,
            W = _inner.W,
        };
    }
}

internal static class TypeConv
{
    internal static float ToFloat(object value)
    {
        if (value is Microsoft.ClearScript.Undefined)
            return 0f;
        return Convert.ToSingle(value);
    }
    internal static object[] ToArray(object value, int minlength = 0)
    {
        if (value is string csa)
        {
            return [.. csa.Split(',').Select(x => x.Trim())];
        }
        if (value is Microsoft.ClearScript.ScriptObject list)
        {
            int given_length = list.GetProperty("length") as int? ?? 0;
            int length = minlength < given_length ? given_length : minlength;

            object[] objArray = new object[length];
            for (int i = 0; i < given_length; i++)
            {
                objArray[i] = list.GetProperty(i.ToString());
            }
            for (int i = given_length; i < length; i++)
            {
                objArray[i] = Microsoft.ClearScript.Undefined.Value;
            }
            return objArray;
        }
        throw new InvalidCastException(
            "Unsupported type: " + value.GetType());
    }
}