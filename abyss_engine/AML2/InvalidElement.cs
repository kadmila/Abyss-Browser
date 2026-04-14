namespace AbyssCLI.AML2;
internal class InvalidElement : Element
{
    public readonly string TagName;
    public InvalidElement(string tag, object? options, DocumentDependencies docDependencies) : base(ElementTag.Invalid, options, docDependencies)
    {
        TagName = tag;
    }
}
