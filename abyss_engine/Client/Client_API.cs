using AbyssCLI.ABI;

namespace AbyssCLI.Client;

public static partial class Client
{
    // MoveWorld may return false (no-op) if the client is overloaded.
    public static bool MoveWorld(string world_url)
    {
        var message = new UIAction()
        {
            MoveWorld = new()
            {
                WorldUrl = world_url
            }
        };
        return _client_operations.Writer.TryWrite(message);
    }
}
