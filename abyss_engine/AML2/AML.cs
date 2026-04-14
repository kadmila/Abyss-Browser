namespace AbyssCLI.AML2;
/// <summary>
/// This is the aml tag
/// </summary>
internal sealed class AML : Element
{
    public AML(object? options, DocumentDependencies docDependencies) : base(ElementTag.Aml, options, docDependencies)
    {
    }
}
