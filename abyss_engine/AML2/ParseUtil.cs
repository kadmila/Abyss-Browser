using Microsoft.Extensions.Options;
using System.Xml;

namespace AbyssCLI.AML2;

internal static class ParseUtil
{
    internal static void ParseAMLDocument(Document target, string document, CancellationToken token)
    {
        XmlDocument xml_document = new();
        xml_document.LoadXml(document);
        string doctype = xml_document.DocumentType?.Name ?? string.Empty;
        if (!(doctype == "aml" || doctype == "AML"))
            throw new ArgumentException("doctype mismatch: " + doctype);

        XmlElement? aml_elem = xml_document.DocumentElement;
        if (aml_elem == null || aml_elem.NodeType != XmlNodeType.Element || aml_elem.Name != "aml")
            throw new ArgumentException("no <aml> : " + aml_elem?.Name ?? "");

        bool is_head_parsed = false;
        bool is_body_parsed = false;
        bool is_warned = false;
        foreach (XmlNode node in aml_elem.ChildNodes)
        {
            if (node.NodeType != XmlNodeType.Element)
                continue;
            switch (node.Name)
            {
            case "head" when !is_head_parsed && !is_body_parsed && node is XmlElement node_elem: // head must be parsed before body
                ParseElement(target, (target.Root.Origin as Element)!, node_elem);
                is_head_parsed = true;
                break;
            case "body" when !is_body_parsed && node is XmlElement node_elem:
                ParseElement(target, (target.Root.Origin as Element)!, node_elem);
                is_body_parsed = true;
                break;
            default:
                if (!is_warned)
                {
                    Client.Client.Cerr.WriteLine("Warning: found <" + node.Name + ">: <aml> may only have a <head> and a <body>, where <head> must come before <body>");
                    is_warned = true;
                }
                break;
            }
        }
    }
    private static void ParseElement(Document document, Element parent, XmlElement element)
    {
        var aml_elem = document.Unsafe_CreateElement(element.Name, element.Attributes);
        parent.L1AddChild(aml_elem);

        foreach (XmlNode child in element.ChildNodes)
        {
            if (child.NodeType != XmlNodeType.Element)
                continue;

            ParseElement(document, aml_elem, (child as XmlElement)!);
        }
    }
}
