using AbyssCLI.HL;

namespace AbyssCLI.AML;

public class Body(ContentB origin) : Transform(origin, "body", null)
{
    public void Init()
    {
        Client.Client.RenderWriter.MoveElement(ElementId, 0);
    }

    public override void remove() =>
        throw new InvalidOperationException("<body> cannot be removed");
}
