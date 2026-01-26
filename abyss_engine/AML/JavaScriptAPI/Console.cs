namespace AbyssCLI.AML.JavaScriptAPI;
#pragma warning disable IDE1006, CA1822 //naming convension, static member
public class Console
{
    public void log(object any) =>
        Client.Client.RenderWriter.ConsolePrint(Helper.StringyfyJsObject(any));
}