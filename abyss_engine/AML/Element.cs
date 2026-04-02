using AbyssCLI.AML.JavaScriptAPI;
using AbyssCLI.HL;
using Microsoft.ClearScript;
using System.Xml;

namespace AbyssCLI.AML;
public class Element : IDisposable
{
    public readonly Content Origin;
    public readonly ElementTag Tag;
    public readonly int ElementId = RenderID.ElementId;
    public readonly Dictionary<string, string> Attributes;
    public Element? Parent;
    public readonly List<Element> Children = [];
    public bool IsDeleteElementRequired = false; // this can be set to false when its parent is deleted in rendering engine.

    public int RefCount; // used by JavaScriptDispatcher
    public Element(Content origin, ElementTag tag, object? options)
    {
        Origin = origin;
        RefCount = 0;
        Client.Client.RenderWriter.CreateElement(-1, ElementId, tag);

        Tag = tag;
        if (options == null)
        {
            Attributes = [];
        }
        else if (options is ScriptObject optionsObj)
        {
            Attributes = Helper.ScriptObjectToDictionaryForceString(optionsObj);
        }
        else if (options is XmlAttributeCollection xmlAttributes)
        {
            Attributes = [];
            foreach (XmlAttribute entry in xmlAttributes)
            {
                Attributes[entry.Name] = entry.Value;
            }
        }
        else
        {
            Client.Client.Cerr.WriteLine("element constructor: option is unsupported type. This is bug");
            Attributes = [];
        }
        GC.AddMemoryPressure(1_000_000_000); //debug
    }
    public Element? GetElementByIdHelper(string _id)
    {
        if (Attributes.TryGetValue("id", out string? id) && id == _id)
        {
            return this;
        }
        foreach (Element child in Children)
        {
            Element? result = child.GetElementByIdHelper(_id);
            if (result != null)
                return result;
        }
        return null;
    }
    public virtual bool IsParentAllowed(Element element) => true;
    public virtual bool IsParentAllowed(string parent_tag) => true;
    public virtual bool IsChildAllowed(Element child) => true;
    public virtual bool IsChildAllowed(string child_tag) => true;

    //JavaScript API exposable
    public void SetActive(bool active) =>
        Client.Client.RenderWriter.ElemSetActive(ElementId, active);
    public virtual Element AppendChild(Element child)
    {
        if (!child.IsParentAllowed(this) || !IsChildAllowed(child))
        {
            throw new InvalidOperationException(
                "<" + Tag + "> cannot have <" + child.Tag + "> as a child");
        }

        if (child == null)
            throw new ArgumentException("[null] is not AmlElement");
        if (child.Parent == this)
            return child;

        if (child.Parent == null)
            Origin.Document.ElementLifespanManager.Connect(child);
        else
            _ = child.Parent.Children.Remove(child);

        child.Parent = this;
        Children.Add(child);
        Client.Client.RenderWriter.MoveElement(child.ElementId, ElementId);
        return child;
    }
    public virtual void Remove()
    {
        if (Parent == null)
            return;

        _ = Parent.Children.Remove(this);
        Parent = null;
        Origin.Document.ElementLifespanManager.Isolate(this);

        Client.Client.RenderWriter.MoveElement(ElementId, -1);
        return;
    }
    private bool _disposed = false;
    public void Dispose()
    {
        if (_disposed)
            return;

        if (IsDeleteElementRequired)
            Client.Client.RenderWriter.DeleteElement(ElementId);

        GC.RemoveMemoryPressure(1_000_000_000); //debug

        GC.SuppressFinalize(this);
        _disposed = true;
    }
    ~Element() => Client.Client.Cerr.WriteLine("fatal:::Element finialized without disposing. This is bug");
}
