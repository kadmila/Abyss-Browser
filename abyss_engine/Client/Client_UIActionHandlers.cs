using AbyssCLI.ABI;
using AbyssCLI.Tool;

namespace AbyssCLI.Client;

public static partial class Client
{
	private static void OnMoveWorld(UIAction.Types.MoveWorld args)
	{
		// Note: In AbyssLibB we don't have local_aurl, so parse as absolute URL
		if (!AbyssURLParser.TryParse(args.WorldUrl, out AbyssURL aurl))
		{
			CerrWriteLine("MoveWorld: failed to parse world url: " + args.WorldUrl);
			return;
		}
		SwapMainWorld(aurl);
	}
	private static void OnShareContent(UIAction.Types.ShareContent args)
	{
		// Note: In AbyssLibB we don't have local_aurl, so parse as absolute URL
		if (!AbyssURLParser.TryParse(args.Url, out AbyssURL content_url))
		{
			CerrWriteLine("OnShareContent: failed to parse address: " + args.Url);
			return;
		}
		_currentWorld.ShareItem(new Guid(args.Uuid.ToByteArray()), content_url, [args.Pos.X, args.Pos.Y, args.Pos.Z, args.Rot.W, args.Rot.X, args.Rot.Y, args.Rot.Z]);
	}
	private static void OnUnshareContent(UIAction.Types.UnshareContent args) => _currentWorld.UnshareItem(new Guid(args.Uuid.ToByteArray()));
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
            if (!_currentWorld._environment.Document.TryEnqueueJavaScript("<console>", args.Text))
            {
                Client.CerrWriteLine("too many javascripts in queue");
            }
        }
    }
}
