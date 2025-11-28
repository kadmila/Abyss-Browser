using AbyssCLI.AML;
using AbyssCLI.Tool;

#nullable enable
namespace AbyssCLI.HL;
internal class ContentB : IDisposable
{
    private readonly AbyssURL _url;
    internal readonly Document Document;
    private readonly CancellationTokenSource _cts;
    private readonly Task _content_task;
    internal ContentB(AbyssURL url, AmlMetadata metadata)
    {
        _url = url;
        Document = new(metadata);
        _cts = new();

        //TODO: properly handle all exceptions from content task.
        _content_task = Task.Run(async() =>
        {
            Document.Init();
            using var _document_cache_ref = Client.Client.Cache.GetReference(_url.ToString());

            Client.Client.CerrWriteLine("getting document cache: " + _url);

            Cache.CachedResource? doc_resource;
            try
            {
                doc_resource = await _document_cache_ref.Task.WaitAsync(_cts.Token);
            }
            catch
            {
                //todo: show loading status/error in UI
                Client.Client.CerrWriteLine("failed to load document body: " + _url);
                return;
            }

            Client.Client.CerrWriteLine("document loaded: " + _url);

            if (doc_resource is not Cache.Text doc_text) //relaxed from text/aml, Cache.Text allows text/* - for compatibility
            {
                throw new Exception("fatal:::MIME mismatch: " + (doc_resource.MIMEType == "" ? "<unspecified>" : doc_resource.MIMEType));
            }
            string raw_document = await doc_text.ReadAsync(_cts.Token);

            ParseUtil.ParseAMLDocument(Document, raw_document, _cts.Token);
            Document.StartJavaScript(_cts.Token);

            Client.Client.CerrWriteLine("document started: " + _url);

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
    }
}
