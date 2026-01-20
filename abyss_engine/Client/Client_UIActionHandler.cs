using AbyssCLI.ABI;

namespace AbyssCLI.Client;

public static partial class Client
{
    private static UIAction ReadProtoMessage()
    {
        int length = _cin.ReadInt32();
        byte[] data = _cin.ReadBytes(length);
        if (data.Length != length)
        {
            throw new IOException("stream closed");
        }
        return UIAction.Parser.ParseFrom(data);
    }
    private static async Task UIReadLoop()
    {
        while (true)
        {
            var message = ReadProtoMessage();
            if (message.InnerCase == UIAction.InnerOneofCase.Kill)
            {
                return;
            }
            await _client_operations.Writer.WriteAsync(message);
        }
    }
    private static async Task UIActionLoop()
    {
        while (true)
        {
            UIAction message = await _client_operations.Reader.ReadAsync();
            switch (message.InnerCase)
            {
                case UIAction.InnerOneofCase.Kill:
                    return;
                case UIAction.InnerOneofCase.MoveWorld:
                    OnMoveWorld(message.MoveWorld);
                    break;
                case UIAction.InnerOneofCase.ShareContent:
                    OnShareContent(message.ShareContent);
                    break;
                case UIAction.InnerOneofCase.UnshareContent:
                    OnUnshareContent(message.UnshareContent);
                    break;
                case UIAction.InnerOneofCase.ConsoleInput:
                    OnConsoleInput(message.ConsoleInput);
                    break;
                default:
                    throw new IOException("fatal: received invalid UI Action");
            }
        }
    }
    private static void OnMoveWorld(UIAction.Types.MoveWorld args)
    {
        _mainWorld?.Dispose();
        _mainWorld = null;

        if (args.WorldUrl.StartsWith("abyss://")) //joining
        {
            var split = args.WorldUrl["abyss://".Length..].Split('/', 2);
            string peer_id;
            string path;
            if (split.Length == 1)
            {
                peer_id = split[0];
                path = "/";
            }
            else if (split.Length == 2)
            {
                peer_id = split[0];
                path = "/" + split[1];
            }
            else
            {
                Cerr.WriteLine("tried to move to invalid world url: " + args.WorldUrl);
                return;
            }

            lock (_worldLock)
            {
                var (net_world, error) = Host.JoinWorld(peer_id, path);
                if (error != null)
                {
                    Cerr.WriteLine("failed to join world: " + error.Message);
                    return;
                }
                _mainWorld = new World(Host, net_world!);
            }
        }
        else if (args.WorldUrl.StartsWith("http://") || args.WorldUrl.StartsWith("https://")) //opening
        {
            lock(_worldLock)
            {
                var (net_world, error) = Host.OpenWorld(args.WorldUrl);
                if (error != null)
                {
                    Cerr.WriteLine("failed to open world: " + error.Message);
                    return;
                }
                _mainWorld = new World(Host, net_world!);
            }
        }
        else
        {
            Cerr.WriteLine("tried to move to invalid world url: " + args.WorldUrl);
        }
    }
    // OnShareContent Opens a new world if _mainWorld is null.
    private static void OnShareContent(UIAction.Types.ShareContent args)
	{
        lock (_worldLock)
        {
            if (_mainWorld == null)
            {
                var (net_world, error) = Host.OpenWorld("");
                if (error != null)
                {
                    Cerr.WriteLine("failed to open empty world: " + error.Message);
                    return;
                }
                _mainWorld = new World(Host, net_world!);
            }

            _mainWorld.ShareItem(new Guid(args.Uuid.ToByteArray()), args.Url, [args.Pos.X, args.Pos.Y, args.Pos.Z, args.Rot.X, args.Rot.Y, args.Rot.Z, args.Rot.W]);
        }
	}
	private static void OnUnshareContent(UIAction.Types.UnshareContent args)
    {
        lock (_worldLock)
        {
            if (_mainWorld == null)
                return;

            _mainWorld.UnshareItem(new Guid(args.Uuid.ToByteArray()));
        }
    }
    private static void OnConsoleInput(UIAction.Types.ConsoleInput args)
    {
        Client.RenderWriter.ConsolePrint("console input: " + args.Text);
        if (args.ElementId == 0) //world environment content
        {
			_mainWorld?.TryExecuteJavascript(args.Text);
        }
    }
}
