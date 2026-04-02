using AbyssCLI.Client;
using AbyssCLI.GraphUtil;

internal class Program
{
    public static async Task Main()
    {
        //await Basics.Test();
        //await Basics.TestObjectAppend();
        //await Cache.TestAbystClientWithCacheCow();
        //Environment.Exit(0);

        Environment.Exit(0);

        try
        {
            await Client.Run();
            Client.Cerr.WriteLine("AbyssCLI terminated peacefully");
        }
        catch (Exception ex)
        {
            Client.Cerr.WriteLine("***FATAL::ABYSS_CLI TERMINATED***\n" + ex.ToString());
        }
    }
}
