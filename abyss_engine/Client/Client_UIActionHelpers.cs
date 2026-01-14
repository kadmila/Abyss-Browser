using AbyssCLI.Tool;

namespace AbyssCLI.Client;

public static partial class Client
{
	public static void SwapMainWorld(AbyssURL url) //can also be called from javascript API.
	{
		lock (_worldMoveLock)
		{
			AbyssLibB.World? net_world;
			AbyssURL world_url;
			
			if (url.Scheme == "abyss")
			{
				// For abyss:// URLs, we would need to join via a peer
				// This requires changes to the API - for now, not supported
				CerrWriteLine("abyss:// URL joining not yet supported in AbyssLibB");
				return;
			}
			else
			{
				var (world, error) = Host.OpenWorld(url.Raw);
				if (error != null)
				{
					CerrWriteLine("failed to open world: " + error.Message);
					return;
				}
				net_world = world;
				world_url = url;
			}

			_currentWorld?.Leave();
			try
			{
				_currentWorld = new World(Host, net_world, world_url);
			}
			catch (Exception ex)
			{
				CerrWriteLine("world creation failed: " + ex.Message);
				_currentWorld = null;
			}
		}
	}
}
