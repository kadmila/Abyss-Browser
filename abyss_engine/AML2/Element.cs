using AbyssCLI.GraphUtil;
using Microsoft.ClearScript;
using System.Xml;

namespace AbyssCLI.AML2;
internal class Element : GraphUtil.L2TreeNode
{
    // Rendering Engine attributes
    protected readonly int ElementId = RenderID.ElementId;

    // AML attributes
    public readonly ElementTag Tag;
    public readonly Dictionary<string, string> Attributes;
    protected readonly DocumentDependencies docDependencies;

    // advanced internals
    //public bool semantically_valid; // For instance, <o> under <head> should have false. Automatically, all of its descendants also.
    public Element(ElementTag tag, object? options, DocumentDependencies docDependencies)
    {
        Tag = tag;
        Client.Client.RenderWriter.CreateElement(-1, ElementId, tag);
        if (options == null)
        {
            Attributes = [];
        }
        else if (options is ScriptObject optionsObj)
        {
            Attributes = JavaScriptAPI.Helper.ScriptObjectToDictionaryForceString(optionsObj);
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
            Attributes = [];
            Client.Client.Cerr.WriteLine("element constructor: option is unsupported type. This is a bug");
        }
        this.docDependencies = docDependencies;
    }

    // Rendering APIs
    public void SetActive(bool active) =>
        Client.Client.RenderWriter.ElemSetActive(ElementId, active);

    // DOM Manipulation Callbacks
    protected override void OnAddChild(L2TreeNode child)
        => Client.Client.RenderWriter.MoveElement(((Element)child).ElementId, ElementId);
    protected override void OnInsertChild(L2TreeNode child, int index) // TODO: This does not work.
        => Client.Client.RenderWriter.MoveElement(((Element)child).ElementId, ElementId);
    protected override void OnIsolate()
        => Client.Client.RenderWriter.MoveElement(ElementId, -1);

    protected override void Dispose(bool is_root)
    {
        if (is_root)
        {
            Client.Client.RenderWriter.MoveElement(ElementId, -1);
        }
        base.Dispose(is_root);
        if (is_root)
        {
            Client.Client.RenderWriter.DeleteElement(ElementId);
        }
    }
}