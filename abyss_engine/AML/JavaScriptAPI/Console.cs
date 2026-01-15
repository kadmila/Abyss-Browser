namespace AbyssCLI.AML.JavaScriptAPI;
#pragma warning disable IDE1006 //naming convension
public class Console
{
    public void log(object any) =>
        Client.Client.RenderWriter.ConsolePrint(any.ToString());
}
#pragma warning restore IDE1006 //naming convension