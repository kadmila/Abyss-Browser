#pragma warning disable IDE1006 //naming convension
namespace AbyssCLI.AML.JavaScriptAPI;

public class Document
{
    private readonly JavaScriptDispatcher _js_dispatcher;
    private readonly AML.Document _origin;
    internal Document(JavaScriptDispatcher js_dispatcher, AML.Document origin)
    {
        _js_dispatcher = js_dispatcher;
        _origin = origin;
    }
    public override string ToString() => "[object AMLDocument]";

    public string title
    {
        get => _origin.Title;
        set => _origin.Title = value;
    }
    public string? iconSrc
    {
        get => _origin.IconSrc;
        set => _origin.IconSrc = value;
    }
    public object body => _js_dispatcher.MarshalElement(_origin.Body)!;
    public object createElement(string tag, object? options) =>
        _js_dispatcher.MarshalElement(_origin.CreateElement(tag, options));
    public object? getElementById(string id)
    {
        AML.Element? result = _origin.GetElementById(id);
        if (result == null)
            return null;

        return _js_dispatcher.MarshalElement(result);
    }
    public bool tryFetchScript(string src) =>
        _origin.TryFetchScript(src);

    //public void open(string url)
    //{
    //    //TODO: open new document
    //    //_origin.
    //}

    //public void close()
    //{
    //    //TODO: close this document
    //}

    public void debug_stat()
    {
        Client.Client.RenderWriter.ConsolePrint(_origin.GetStatistics(""));
    }
}
