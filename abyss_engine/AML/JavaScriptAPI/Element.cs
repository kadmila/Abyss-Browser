#nullable enable
#pragma warning disable IDE1006 //naming convension
namespace AbyssCLI.AML.JavaScriptAPI;

public class Element
{
    protected readonly JavaScriptDispatcher _js_dispatcher;
    protected readonly AML.Element _origin;
    internal Element(JavaScriptDispatcher js_dispatcher, AML.Element origin)
    {
        _js_dispatcher = js_dispatcher;
        _origin = origin;
    }

    public override string ToString() => "[object AML" + GetType().Name + "]";
    public object children => _js_dispatcher.MarshalElementArray(_origin.Children);
    public void setActive(bool active) => _origin.SetActive(active);
    public object appendChild(Element child) => _origin.AppendChild(child._origin);
    public void remove() => _origin.Remove();
}
