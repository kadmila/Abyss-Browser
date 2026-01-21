using AbyssCLI.HL;

namespace AbyssCLI.AML;

public class Body(Content origin) : Transform(origin, ElementTag.O, null)
{
    public void Init()
    {
        Client.Client.RenderWriter.MoveElement(ElementId, 0);
    }

    public override void Remove() =>
        throw new InvalidOperationException("<body> cannot be removed");
}
