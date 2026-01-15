using AbyssCLI.ABI;

namespace AbyssCLI.Client;

public static partial class Client
{
    public static async Task MoveWorldAsync(string world_url)
    {
        var message = new UIAction()
        {
            MoveWorld = new()
            {
                WorldUrl = world_url
            }
        };
        await _client_operations.Writer.WriteAsync(message);
    }
}
