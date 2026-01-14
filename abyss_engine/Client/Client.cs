using AbyssCLI.ABI;
using AbyssCLI.Tool;

namespace AbyssCLI.Client;

public static partial class Client
{
	public static readonly AbyssLibB.Host Host;
	public static readonly SingleThreadTaskRunner CachedResourceWorker = new();
	public static readonly RenderActionWriter RenderWriter = new(Console.OpenStandardOutput())
	{
		AutoFlush = true
	};
	public static readonly HttpClient HttpClient = new()
	{
		Timeout = TimeSpan.FromSeconds(10)
	};
    public static readonly AbyssLibB.AbystClient AbystClient;
    public static readonly AbyssLibB.Http3Client CollocatedHttp3Client;
    public static readonly Cache.Cache Cache;

    private static readonly BinaryReader _cin = new(Console.OpenStandardInput());
	private static readonly StreamWriter _cerr = new(Stream.Synchronized(Console.OpenStandardError()))
	{
		AutoFlush = true
	};
    private static readonly Thread _hostEventThread;
    private static World _currentWorld;
	private static readonly object _worldMoveLock = new();

	const bool _manual_construction = true; // for debugging purpose, bypasses initialization message listening

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
			lock (_worldMoveLock)
			{
				_currentWorld?.HandleEvent(evnt);
			}
		}
	}

	static Client()
	{
		if (AbyssLibB.Initialize() != 0)
        {
            CerrWriteLine("failed to initialize abyssnet.dll");
            return;
		}

		if (_manual_construction) // debug
        {
            RenderWriter = new(NoOpStream.Instance);

            string pemPath = "testkey.pem";
            if (!File.Exists(pemPath))
            {
                Console.WriteLine($"Error: {pemPath} not found in project root directory");
                Environment.Exit(1);
            }

            byte[] keyBytes = File.ReadAllBytes(pemPath);
            var (host, hostErr) = AbyssLibB.Host.Create(keyBytes);
            if (hostErr != null)
            {
                CerrWriteLine("host creation failed: " + hostErr.Message);
                return;
            }
            Host = host!;
        }
		else
        {
            //Host Initialization
            UIAction initMsg = ReadProtoMessage();
            if (initMsg.InnerCase != UIAction.InnerOneofCase.Init)
            {
                CerrWriteLine("host not initialized");
                return;
            }

            var (host, hostErr) = AbyssLibB.Host.Create(initMsg.Init.RootKey.ToByteArray());
            if (hostErr != null)
            {
                CerrWriteLine("host creation failed: " + hostErr.Message);
                return;
            }
            Host = host!;
        }
		
		var bindErr = Host.Bind();
		if (bindErr != null)
		{
			CerrWriteLine("host bind failed: " + bindErr.Message);
			return;
		}

        // Start serving in background
        Host.Serve();
		
		// Start host event loop thread
		_hostEventThread = new Thread(HostEventLoop)
		{
			IsBackground = true,
			Name = "HostEventLoop"
		};
		_hostEventThread.Start();
		
		// Create reusable AbystClient
		AbystClient = Host.NewAbystClient();

        // Create reusable CollocatedHttp3Client
        CollocatedHttp3Client = Host.NewCollocatedHttp3Client();

        // Register local info for rendering engine
        RenderWriter.LocalInfo("abyss://" + Host.ID, Host.ID);

		Cache = new(
			http_request => Task.Run(async () =>
			{
				HttpResponseMessage result = await HttpClient.SendAsync(http_request, HttpCompletionOption.ResponseHeadersRead);

				string? mime = result.Content.Headers.ContentType?.MediaType;
				Cache!.Patch(http_request.RequestUri!.ToString(), mime switch
				{
					"model/obj" or "image/png" => new Cache.StaticSimpleResource(result),
					"image/jpeg" => new Cache.StaticResource(result),
					_ when mime != null && mime.StartsWith("text/") => new Cache.Text(result),
					_ => new Cache.StaticSimpleResource(result),
				});
			}),
			abyst_request => Task.Run(async () =>
			{
				var (response, error) = await AbystClient.Get(abyst_request.AbyssURL.Id, abyst_request.AbyssURL.Path);
				if (error != null)
				{
					CerrWriteLine("abyst request failed: " + error.Message);
					return;
				}

                byte[] body = response!.ReadAllBody();
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

				Cache!.Patch(abyst_request.AbyssURL.ToString(), mime switch
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
		
		//var (net_world, worldError) = Host.OpenWorld(default_world_url_raw);
		//if (worldError != null)
		//{
		//	CerrWriteLine("failed to open default world: " + worldError.Message);
		//	return;
		//}
		//_currentWorld = new World(Host, net_world!, default_world_url);
	}
}


public sealed class NoOpStream : Stream
{
    public static readonly NoOpStream Instance = new NoOpStream();

    private NoOpStream()
    {
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => true;

    public override long Length => 0;
    public override long Position
    {
        get => 0;
        set
        {
        }
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        // EOF immediately
        return 0;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        return 0;
    }

    public override void SetLength(long value)
    {
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        // discard
    }

    protected override void Dispose(bool disposing)
    {
        // no resources to release
    }
}