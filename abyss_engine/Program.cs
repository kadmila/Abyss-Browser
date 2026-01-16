using AbyssCLI.Client;
using AbyssCLI.Test;

internal class Program
{
    public static async Task Main()
    {
        //await Cache.TestAbystClientWithCacheCow();
        //Environment.Exit(0);

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
