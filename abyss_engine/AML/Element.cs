using AbyssCLI.HL;
using Microsoft.ClearScript;
using System.Xml;

namespace AbyssCLI.AML;

#nullable enable
#pragma warning disable IDE1006 //naming convension
public class Element : IDisposable
{
    public readonly ContentB Origin;
    public int RefCount;
    public readonly int ElementId = RenderID.ElementId;
    public readonly string tagName;
    public readonly Dictionary<string, string> Attributes = [];
    public Element? Parent;
    public readonly List<Element> Children = [];
    public bool IsDeleteElementRequired = false; // this can be set to false when its parent is deleted in rendering engine.
    public Element(ContentB origin, string tag, object? options)
    {
        Origin = origin;
        RefCount = 0;
        Client.Client.RenderWriter.CreateElement(-1, ElementId, tag switch
        {
            "o" => ElementTag.O,
            "obj" => ElementTag.Obj,
            "pbrm" => ElementTag.Pbrm,
            "body" => ElementTag.O,
            "bcol" => ElementTag.Bcol,
            _ => throw new InvalidOperationException()
        });

        tagName = tag;
        if (options is ScriptObject optionsObj)
        {
            foreach (string prop in optionsObj.PropertyNames)
            {
                string? value = optionsObj.GetProperty(prop)?.ToString();
                if (value != null)
                    Attributes[prop] = value;
            }
        }
        else if (options is XmlAttributeCollection xmlAttributes)
        {
            foreach (XmlAttribute entry in xmlAttributes)
            {
                Attributes[entry.Name] = entry.Value;
            }
        }
        GC.AddMemoryPressure(1_000_000_000); //debug
    }
    public Element? getElementByIdHelper(string _id)
    {
        if (Attributes.TryGetValue("id", out string? id) && id == _id)
        {
            return this;
        }
        foreach (Element child in Children)
        {
            Element? result = child.getElementByIdHelper(_id);
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
    public void setActive(bool active) =>
        Client.Client.RenderWriter.ElemSetActive(ElementId, active);
    public virtual Element appendChild(Element child)
    {
        if (!child.IsParentAllowed(this) || !IsChildAllowed(child))
        {
            throw new InvalidOperationException(
                "<" + tagName + "> cannot have <" + child.tagName + "> as a child");
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
    public virtual void remove()
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
    ~Element() => Client.Client.CerrWriteLine("fatal:::Element finialized without disposing. This is bug");
}
#pragma warning restore IDE1006 //naming convension

