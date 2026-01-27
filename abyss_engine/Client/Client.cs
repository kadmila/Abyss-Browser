// Bypasses initialization message listening, setup for debugging
//#define	TESTING_SETUP

using AbyssCLI.ABI;
using CacheCow.Client;
using System.Threading.Channels;

namespace AbyssCLI.Client;

#pragma warning disable CS8618 // analyzer bug in static constructor

public static partial class Client
{
    public static readonly AbyssLibB.Host Host;
	public static readonly RenderActionWriter RenderWriter = new(Console.OpenStandardOutput())
	{
		AutoFlush = true
	};
    public static readonly StreamWriter Cerr = new(Stream.Synchronized(Console.OpenStandardError()))
    {
        AutoFlush = true
    };

    // HttpClient and CollocatedHttp3Client shares cookies container, but Abyst has separate one.
    public static readonly System.Net.CookieContainer SharedCookieContainer = new();
    public static readonly System.Net.CookieContainer AbystCookieContainer = new();

    public static readonly HttpClient HttpClient; // normal web fetch
	public static readonly HttpClient AbystClient; // abyst:// scheme
	public static readonly HttpClient CollocatedHttp3Client; // collocated http/3 fetch

    private static readonly BinaryReader _cin = new(Console.OpenStandardInput());

    private static readonly object _worldLock = new();
    private static World? _mainWorld;

    // For client-level call serialization (UI/JavaScript APIs)
    private static readonly Channel<UIAction> _client_operations = Channel.CreateUnbounded<UIAction>(new UnboundedChannelOptions
    {
        SingleReader = true,
        SingleWriter = false
    });

    static Client()
	{
		if (AbyssLibB.Initialize() != 0)
        {
            Cerr.WriteLine("failed to initialize abyssnet.dll");
            return;
		}

#if TESTING_SETUP
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
            Cerr.WriteLine("host creation failed: " + hostErr.Message);
            return;
        }
        Host = host!;
#else
        //Host Initialization
        UIAction initMsg = ReadProtoMessage();
        if (initMsg.InnerCase != UIAction.InnerOneofCase.Init)
        {
            Cerr.WriteLine("host not initialized");
            return;
        }

        var (host, hostErr) = AbyssLibB.Host.Create(initMsg.Init.RootKey.ToByteArray());
        if (hostErr != null)
        {
            Cerr.WriteLine("host creation failed: " + hostErr.Message);
            return;
        }
        Host = host!;
#endif

        var bindErr = Host.Bind();
		if (bindErr != null)
		{
			Cerr.WriteLine("host bind failed: " + bindErr.Message);
			return;
		}

        // Start serving in background
        Host.Serve();

		// Create reusable HttpClient with shared cookie container
		// This enables automatic cookie management for standard HTTP requests
		var http_handler = new System.Net.Http.HttpClientHandler
		{
			CookieContainer = SharedCookieContainer,
			UseCookies = true
		};
		HttpClient = ClientExtensions.CreateClient(http_handler);
		
		// Create reusable AbystClient (no cookie sharing - different protocol)
		AbystClient = ClientExtensions.CreateClient(new AbyssHttp.AbystHttpMessageHandler(Host.NewAbystClient(), AbystCookieContainer));

		// Create reusable CollocatedHttp3Client with shared cookie container
		// This enables cookie sharing with the regular HttpClient for HTTPS requests
		CollocatedHttp3Client = ClientExtensions.CreateClient(
			new AbyssHttp.CollocatedH3HttpMessageHandler(Host.NewCollocatedHttp3Client(), SharedCookieContainer));

        // Register local info for rendering engine
        RenderWriter.LocalInfo("abyss://" + Host.ID, Host.ID);
    }
    public static async Task Run()
    {
        // HostEventLoop requires a dedicated thread (hot path)
        var host_th = new Thread(HostEventLoop)
        {
            IsBackground = true,
            Name = "HostEventLoop"
        };
        host_th.Start();

        var ui_read_task = Task.Run(UIReadLoop); // Should we assign native thread for this? IDK
        
        // main loop
        await UIActionLoop();
        
        await ui_read_task;
        host_th.Join();
    }
}

public sealed class NoOpStream : Stream
{
    public static readonly NoOpStream Instance = new();

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

    public override void Flush() { }
    public override int Read(byte[] buffer, int offset, int count)
    {
        return 0;
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        return 0;
    }
    public override void SetLength(long value) { }
    public override void Write(byte[] buffer, int offset, int count) { }
    protected override void Dispose(bool disposing)
    {
        // no resources to release
        base.Dispose(disposing);
    }
}