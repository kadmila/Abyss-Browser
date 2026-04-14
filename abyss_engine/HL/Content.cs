using AbyssCLI.AML2;
using System.Collections.Concurrent;

namespace AbyssCLI.HL;
public class Content : IDisposable
{
    public readonly System.Uri URL;
    public readonly Cache.Cache Cache;

    private readonly CancellationTokenSource cts;
    private readonly BlockingCollection<(string, string)> jsQueue;
    private readonly Document Document;
    private readonly JavaScriptDispatcher jsDispatcher;
    private readonly Task content_task;
    public Content(string url, AmlMetadata metadata)
    {
        URL = new(url);
        Cache = new();

        cts = new();
        jsQueue = [];
        Document = new(new(Cache, jsQueue.Add), metadata);
        jsDispatcher = new(jsQueue, new(), Document);

        //TODO: properly handle all exceptions from content task.
        content_task = Task.Run(async () =>
        {
            using var _document_cache_ref = Cache.GetReference(url);
            Cache.CachedResource? doc_resource;
            try
            {
                doc_resource = await _document_cache_ref.Task.WaitAsync(cts.Token);
            }
            catch(Exception e)
            {
                //todo: show loading status/error in UI
                Client.Client.Cerr.WriteLine("failed to load content(" + url + "): " + e.Message);
                return;
            }

            if (doc_resource is not Cache.Text doc_text) //relaxed from text/aml, Cache.Text allows text/* - for compatibility
            {
                Client.Client.Cerr.WriteLine("fatal:::MIME mismatch(" + url + "): " + (doc_resource.MIMEType == "" ? "<unspecified>" : doc_resource.MIMEType));
                return;
            }

            string raw_document;
            try
            {
                raw_document = await doc_text.ReadAsync(cts.Token);
            }
            catch(Exception e)
            {
                //todo: show loading status/error in UI
                Client.Client.Cerr.WriteLine("failed to load AML(" + url + "): " + e.Message);
                return;
            }
            //Client.Client.Cerr.WriteLine("document loaded: " + url);

            try
            {
                ParseUtil.ParseAMLDocument(Document, raw_document, cts.Token);
            }
            catch (Exception e)
            {
                //todo: show loading status/error in UI
                Client.Client.Cerr.WriteLine("failed to parse AML(" + url + "): " + e.Message);
                return;
            }

            jsDispatcher.Run(cts.Token); // This returns when the token is cancelled.
        });
    }
    public string TranslateURL(string url)
    {
        var result = new System.Uri(URL, url);
        return result.ToString();
    }
    public void InjectJavaScript(string filename, string jsCode)
    {
        jsQueue.Add((filename, jsCode));
    }

    private bool is_disposed;
    public void Dispose()
    {
        if (is_disposed)
            return;

        cts.Cancel();
        try
        {
            content_task.Wait();
        }
        catch (Exception ex)
        {
            Client.Client.RenderWriter.ConsolePrint("***FATAL***: uncaught exception from content: " + ex.ToString());
        }
        content_task.Dispose();
        jsDispatcher.Dispose();
        Document.Dispose();

        is_disposed = true;
        GC.SuppressFinalize(this);
    }
    ~Content()
    {
        Client.Client.Cerr.WriteLine("***FATAL***: Content was garbage collected. Content must be Disposed. This is a bug");
    }
}