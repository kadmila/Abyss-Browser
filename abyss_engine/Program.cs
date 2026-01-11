using AbyssCLI.Client;
using AbyssCLI.Test;

internal class Program
{
    public static async Task Main()
    {
        await Basics.TestObjectAppend();
        Environment.Exit(0);

        try
        {
            Client.Init();
            await Client.Run();
            Client.CerrWriteLine("AbyssCLI terminated peacefully");
        }
        catch (Exception ex)
        {
            Client.CerrWriteLine("***FATAL::ABYSS_CLI TERMINATED***\n" + ex.ToString());
        }
    }
}
