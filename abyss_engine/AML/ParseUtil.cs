using AbyssCLI.HL;
using System.Xml;

namespace AbyssCLI.AML;

internal static class ParseUtil
{
    internal static void ParseAMLDocument(Document target, string document, CancellationToken token)
    {
        XmlDocument xml_document = new();
        xml_document.LoadXml(document);
        string doctype = xml_document.DocumentType?.Name ?? string.Empty;
        if (doctype != "aml")
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
                ParseHead(target, node_elem);
                is_head_parsed = true;
                break;
            case "body" when !is_body_parsed && node is XmlElement node_elem:
                ParseBody(target, node_elem, token);
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
    private static void ParseHead(Document document, XmlElement head_elem)
    {
        foreach (XmlNode child in head_elem.ChildNodes)
        {
            if (child.NodeType != XmlNodeType.Element)
                continue;
            switch (child.Name)
            {
            case "script":
                ParseScript(document, (child as XmlElement)!);
                break;
            case "title":
            {
                XmlNode? text_node = child.FirstChild;
                if (text_node == null)
                    continue;
                if (text_node.NodeType != XmlNodeType.Text || text_node.Value == null)
                {
                    Client.Client.Cerr.WriteLine("AML parsing failure: <title> tag must only have text content");
                    continue;
                }
                document.Title = text_node.Value;
            }
            break;
            case "link":
                ParseLink(document, (child as XmlElement)!);
                break;
            default:
                break;
            }
        }
    }
    private static void ParseScript(Document document, XmlElement script_elem)
    {
        // src - defer is the default behavior.
        string src = script_elem.GetAttribute("src");
        if (src != null && src.Length > 0)
        {
            if (!document.TryFetchScript(src))
                Client.Client.Cerr.WriteLine("Ignored: too many scripts");

            return;
        }

        // direct text script
        XmlNode? text_node = script_elem.FirstChild;
        if (text_node == null)
        {
            Client.Client.Cerr.WriteLine("Warning: empty <script>");
            return;
        }
        if (text_node.NodeType != XmlNodeType.Text)
        {
            Client.Client.Cerr.WriteLine("Error: text <script> should only have text");
            return;
        }
        if (!document.TryRunScript("<script>", text_node.Value ?? ""))
            Client.Client.Cerr.WriteLine("Ignored: too many scripts");
    }
    private static void ParseLink(Document document, XmlElement link_elem)
    {
        string href = link_elem.GetAttribute("href");
        switch (link_elem.GetAttribute("rel"))
        {
        case "icon":
            document.IconSrc = href;
            break;
        default:
            return;
        }
    }
    private static void ParseBody(Document document, XmlElement target_elem, CancellationToken token)
    {
        Body body = document.Body;
        //body exists already in document.body, but we need to apply attributes.
        foreach (XmlAttribute entry in target_elem.Attributes)
        {
            switch (entry.Name)
            {
            case "pos":
                body.pos = entry.Value;
                break;
            case "rot":
                body.rot = entry.Value;
                break;
            default:
                break;
            }
        }

        //children
        ParseBodyElement(document, document.Body, target_elem, token);
    }
    private static void ParseBodyElement(Document document, Element target, XmlElement target_elem, CancellationToken token)
    {
        foreach (XmlNode child in target_elem.ChildNodes)
        {
            if (child.NodeType != XmlNodeType.Element)
                continue;

            Element elem = document.CreateElement(child.Name, child.Attributes);
            _ = target.AppendChild(elem);
            ParseBodyElement(document, elem, (child as XmlElement)!, token);
        }
    }
}
