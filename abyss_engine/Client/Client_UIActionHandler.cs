using AbyssCLI.ABI;
using AbyssCLI.Tool;
using System;

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
                case UIAction.InnerOneofCase.ConnectPeer:
                    OnConnectPeer(message.ConnectPeer);
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
        lock (_worldMoveLock)
        {
            var (net_world, error) = Host.OpenWorld(args.WorldUrl);
            if (error != null)
            {
                CerrWriteLine("failed to open world: " + error.Message);
                return;
            }

            _currentWorld?.Dispose();
            try
            {
                _currentWorld = new World(Host, net_world!);
            }
            catch (Exception ex)
            {
                CerrWriteLine("world creation failed: " + ex.Message);
                _currentWorld = null;
            }
        }
    }
	private static void OnShareContent(UIAction.Types.ShareContent args)
	{
		_currentWorld!.ShareItem(new Guid(args.Uuid.ToByteArray()), args.Url, [args.Pos.X, args.Pos.Y, args.Pos.Z, args.Rot.W, args.Rot.X, args.Rot.Y, args.Rot.Z]);
	}
	private static void OnUnshareContent(UIAction.Types.UnshareContent args) => _currentWorld!.UnshareItem(new Guid(args.Uuid.ToByteArray()));
	private static void OnConnectPeer(UIAction.Types.ConnectPeer args)
	{
		// In AbyssLibB, use Dial() instead of OpenOutboundConnection
		var error = Host.Dial(args.Aurl);
		if (error != null)
		{
			CerrWriteLine("failed to dial peer: " + error.Message);
		}
	}
    private static void OnConsoleInput(UIAction.Types.ConsoleInput args)
    {
        Client.RenderWriter.ConsolePrint("console input: " + args.Text);
        if (args.ElementId == 0) //world environment content
        {
			_currentWorld!.TryExecuteJavascript(args.Text);
        }
    }
}
