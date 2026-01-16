using AbyssCLI.AML;

#nullable enable
namespace AbyssCLI.HL;
public class ContentB : IDisposable
{
    public readonly Cache.Cache Cache = new();

    private readonly string _url;
    internal readonly Document Document;
    private readonly CancellationTokenSource _cts;
    private readonly Task _content_task;
    internal ContentB(string url, AmlMetadata metadata)
    {
        _url = url;
        Document = new(this, metadata);
        _cts = new();

        //TODO: properly handle all exceptions from content task.
        _content_task = Task.Run(async() =>
        {
            Document.Init();
            using var _document_cache_ref = Cache.GetReference(_url);

            Cache.CachedResource? doc_resource;
            try
            {
                doc_resource = await _document_cache_ref.Task.WaitAsync(_cts.Token);
            }
            catch
            {
                //todo: show loading status/error in UI
                Client.Client.Cerr.WriteLine("failed to load document body: " + _url);
                return;
            }

            if (doc_resource is not Cache.Text doc_text) //relaxed from text/aml, Cache.Text allows text/* - for compatibility
            {
                Client.Client.Cerr.WriteLine("fatal:::MIME mismatch: " + (doc_resource.MIMEType == "" ? "<unspecified>" : doc_resource.MIMEType));
                return;
            }

            string raw_document;
            try
            {
                raw_document = await doc_text.ReadAsync(_cts.Token);
            } 
            catch
            {
                Client.Client.Cerr.WriteLine("failed to read document: " + _url);
                return;
            }

            Client.Client.Cerr.WriteLine("document loaded: " + _url);

            ParseUtil.ParseAMLDocument(this, Document, raw_document, _cts.Token);
            Document.StartJavaScript(_cts.Token);

            while (true)
            { //temporary: fixed duration cleanup
                try
                {
                    await Task.Delay(1000, _cts.Token);
                }
                catch
                {
                    break;
                }
                Document.ScheduleOphanedElementCleanup();
            }
        });
    }

    private bool is_disposed;
    public void Dispose()
    {
        if (is_disposed)
            return;

        _cts.Cancel();
        Document.Interrupt();
        try
        {
            _content_task.Wait();
        }
        catch (Exception ex)
        {
            Client.Client.RenderWriter.ConsolePrint("***FATAL***: uncaught exception from content: " + ex.ToString());
        }
        Document.Join();

        is_disposed = true;
        GC.SuppressFinalize(this);
    }
    ~ContentB() => Dispose();
}
