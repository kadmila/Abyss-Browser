using AbyssCLI.ABI;
using AbyssCLI.Tool;
using static AbyssCLI.ABI.UIAction.Types;

namespace AbyssCLI.Client;

public static partial class Client
{
	public static AbyssLibB.Host Host
	{
		get; private set;
	}
	public static Cache.Cache Cache
	{
		get; private set;
	}
	public static readonly SingleThreadTaskRunner CachedResourceWorker = new();
	public static readonly RenderActionWriter RenderWriter = new(Console.OpenStandardOutput())
	{
		AutoFlush = true
	};
	public static readonly HttpClient HttpClient = new()
	{
		Timeout = TimeSpan.FromSeconds(10)
	};

	private static readonly BinaryReader _cin = new(Console.OpenStandardInput());
	private static readonly StreamWriter _cerr = new(Stream.Synchronized(Console.OpenStandardError()))
	{
		AutoFlush = true
	};
	private static AbyssLibB.AbystClient _abystClient;
	private static World _current_world;
	private static readonly object _world_move_lock = new();
	private static Thread _hostEventThread;

	public static void CerrWriteLine(string message) => _cerr.WriteLine(message);
	
	// Host event loop - dispatches events to appropriate world
	private static void HostEventLoop()
	{
		while (true)
		{
			var (evnt, error) = Host.WaitForEvent();
			if (error != null)
			{
				CerrWriteLine("Host event error: " + error.Message);
				return;
			}
			
			// Handle peer connection events at host level
			if (evnt is AbyssLibB.EPeerConnected peerConnected)
			{
				CerrWriteLine($"Peer connected: {peerConnected.Peer.ID}");
				// We could store the peer handle here if needed
				continue;
			}
			
			if (evnt is AbyssLibB.EPeerDisconnected peerDisconnected)
			{
				CerrWriteLine($"Peer disconnected: {peerDisconnected.PeerID}");
				continue;
			}
			
			// Dispatch world events to current world
			lock (_world_move_lock)
			{
				_current_world?.HandleEvent(evnt);
			}
		}
	}

	public static void Init()
	{
		if (AbyssLibB.Initialize() != 0)
		{
			throw new Exception("failed to initialize abyssnet.dll");
		}

		//Host Initialization
		UIAction init_msg = ReadProtoMessage();
		if (init_msg.InnerCase != UIAction.InnerOneofCase.Init)
		{
			throw new Exception("host not initialized");
		}
		
		var (host, hostError) = AbyssLibB.Host.Create(init_msg.Init.RootKey.ToByteArray());
		if (hostError != null)
		{
			CerrWriteLine("host creation failed: " + hostError.Message);
			return;
		}
		Host = host;
		
		var bindError = Host.Bind();
		if (bindError != null)
		{
			CerrWriteLine("host bind failed: " + bindError.Message);
			return;
		}
		
		// Start serving in background
		Task.Run(() => Host.Serve());
		
		// Start host event loop thread
		_hostEventThread = new Thread(HostEventLoop)
		{
			IsBackground = true,
			Name = "HostEventLoop"
		};
		_hostEventThread.Start();
		
		// Create reusable AbystClient
		_abystClient = Host.NewAbystClient();
		
		RenderWriter.LocalInfo("abyss://" + Host.ID, Host.ID);

		Cache = new(
			http_request => Task.Run(async () =>
			{
				HttpResponseMessage result = await HttpClient.SendAsync(http_request, HttpCompletionOption.ResponseHeadersRead);

				string mime = result.Content.Headers.ContentType.MediaType;
				Cache.Patch(http_request.RequestUri.ToString(), mime switch
				{
					"model/obj" or "image/png" => new Cache.StaticSimpleResource(result),
					"image/jpeg" => new Cache.StaticResource(result),
					_ when mime.StartsWith("text/") => new Cache.Text(result),
					_ => new Cache.StaticSimpleResource(result),
				});
			}),
			abyst_request => Task.Run(async () =>
			{
				CerrWriteLine("abyst cache get: " + abyst_request.AbyssURL.ToString());
				
				var (response, error) = await _abystClient.Get(abyst_request.AbyssURL.Id, abyst_request.AbyssURL.Path);
				if (error != null)
				{
					CerrWriteLine("abyst request failed: " + error.Message);
					return;
				}
				
				byte[] body = response.ReadAllBody();
				HttpResponseMessage result = new((System.Net.HttpStatusCode)response.StatusCode)
				{
					Content = new ByteArrayContent(body)
				};
				
				var mime = response.GetHeader("Content-Type") ?? "unknown";
				{//remove charset/format suffix
					int index = mime.IndexOf(';');
					if (index >= 0)
						mime = mime[..index];
				}
				CerrWriteLine("abyst patch: " + abyst_request.AbyssURL.ToString());

				Cache.Patch(abyst_request.AbyssURL.ToString(), mime switch
				{
					"model/obj" or "image/png" => new Cache.StaticSimpleResource(result),
					"image/jpeg" => new Cache.StaticResource(result),
					_ when mime.StartsWith("text/") => new Cache.Text(result),
					_ => new Cache.StaticSimpleResource(result),
				});
				CerrWriteLine("abyst patch done: " + abyst_request.AbyssURL.ToString());
				
				response.Dispose();
			})
		);
		CachedResourceWorker.Start();

		//string default_world_url_raw = "abyst:" + Host.ID;
		string default_world_url_raw = "http://127.0.0.1:7777/";
		if (!AbyssURLParser.TryParse(default_world_url_raw, out AbyssURL default_world_url))
		{
			CerrWriteLine("default world url parsing failed");
			return;
		}
		
		var (net_world, worldError) = Host.OpenWorld(default_world_url_raw);
		if (worldError != null)
		{
			CerrWriteLine("failed to open default world: " + worldError.Message);
			return;
		}
		_current_world = new World(Host, net_world, default_world_url);
	}
}