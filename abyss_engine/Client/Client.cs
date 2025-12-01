using AbyssCLI.ABI;
using AbyssCLI.Tool;
using static AbyssCLI.ABI.UIAction.Types;

namespace AbyssCLI.Client;

public static partial class Client
{
    public static AbyssLib.Host Host
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
    private static AbyssLib.SimplePathResolver _resolver;
    private static World _current_world;
    private static readonly object _world_move_lock = new();

    public static void CerrWriteLine(string message) => _cerr.WriteLine(message);

    public static void Init()
    {
        if (AbyssLib.Init() != 0)
        {
            throw new Exception("failed to initialize abyssnet.dll");
        }
        _resolver = AbyssLib.NewSimplePathResolver();

        //Host Initialization
        UIAction init_msg = ReadProtoMessage();
        if (init_msg.InnerCase != UIAction.InnerOneofCase.Init)
        {
            throw new Exception("host not initialized");
        }
        string abyst_server_path = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + "\\ABYST\\" + init_msg.Init.Name;
        if (!Directory.Exists(abyst_server_path))
        {
            _ = Directory.CreateDirectory(abyst_server_path);
        }
        CerrWriteLine("abyst server path: " + abyst_server_path);
        Host = AbyssLib.OpenAbyssHost(init_msg.Init.RootKey.ToByteArray(), _resolver, AbyssLib.NewSimpleAbystServer(abyst_server_path));
        if (!Host.IsValid())
        {
            CerrWriteLine("host creation failed: " + AbyssLib.GetError().ToString());
            return;
        }
        RenderWriter.LocalInfo(Host.local_aurl.Raw, Host.local_aurl.Id);

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
            abyst_request => Task.Run(() =>
            {
                CerrWriteLine("abyst cache get: " + abyst_request.AbyssURL.ToString());
                var get_abyst_client_result = Host.GetAbystClient(abyst_request.AbyssURL.Id);
                if (!get_abyst_client_result.Item2.Empty)
                {
                    CerrWriteLine("abyst client creation failed: " + get_abyst_client_result.Item2.Message);
                    return;
                }
                var AbystClient = get_abyst_client_result.Item1;

                var response = AbystClient.Request(AbyssLib.AbystRequestMethod.GET, abyst_request.AbyssURL.Path);
                _ = response.TryLoadBodyAll();
                HttpResponseMessage result = new((System.Net.HttpStatusCode)response.Code)
                {
                    Content = new ByteArrayContent(response.Body)
                };
                var mime = response.Header.TryGetValue("Content-Type", out var content_types) ? content_types[0] : "unknown";
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
            })
        );
        CachedResourceWorker.Start();

        //string default_world_url_raw = "abyst:" + Host.local_aurl.Id;
        string default_world_url_raw = "http://127.0.0.1:7777/";
        if (!AbyssURLParser.TryParse(default_world_url_raw, out AbyssURL default_world_url))
        {
            CerrWriteLine("default world url parsing failed");
            return;
        }
        AbyssLib.World net_world = Host.OpenWorld(default_world_url_raw);
        _current_world = new World(Host, net_world, default_world_url);
        if (!_resolver.TrySetMapping("", net_world.world_id).Empty)
            throw new Exception("faild to set path for initial world at default path");
    }
}