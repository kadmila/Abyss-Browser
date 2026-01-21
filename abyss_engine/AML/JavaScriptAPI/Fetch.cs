using Microsoft.ClearScript;
using Microsoft.ClearScript.JavaScript;
using Microsoft.ClearScript.V8;
using System.Text;

namespace AbyssCLI.AML.JavaScriptAPI;

#pragma warning disable IDE1006 //naming convension
public class FetchApi
{
    public readonly V8ScriptEngine Engine;
    public FetchApi(V8ScriptEngine engine) => Engine = engine;

    // Fetch the content from a URL
    public object FetchAsync(object? url, object? options) =>
        JavaScriptExtensions.ToPromise(FetchInternalAsync(url as string ?? string.Empty, options as ScriptObject), Engine);
    private async Task<Response> FetchInternalAsync(string url, ScriptObject? options)
    {
        //Client.Client.RenderWriter.ConsolePrint("fetch called, option: " + options?.ToString());
        var request = createRequestFromFetch(url, options);
        bool is_collocated_h3 = options != null && (options.GetProperty("abyss-collocated-http3") as bool? ?? false);

        HttpClient client;
        if (url.StartsWith("abyst")) {
            client = Client.Client.AbystClient;
        }
        else if(is_collocated_h3)
        {
            client = Client.Client.CollocatedHttp3Client;
        }
        else
        {
            client = Client.Client.HttpClient;
        }

        var response = await client.SendAsync(request);
        return new Response(this, response);
    }
    private static HttpRequestMessage createRequestFromFetch(string url, ScriptObject? options)
    {
        var request = new HttpRequestMessage
        {
            RequestUri = new Uri(url)
        };

        if (options == null)
        {
            request.Method = HttpMethod.Get;
            return request;
        }

        // Method
        if (options.GetProperty("method") is string method)
        {
            request.Method = new HttpMethod(method.ToUpperInvariant());
        }
        else
        {
            request.Method = HttpMethod.Get;
        }

        // Headers
        if (options.GetProperty("headers") is ScriptObject headers)
        {
            foreach (var name in headers.PropertyNames)
            {
                var value = headers.GetProperty(name)?.ToString();
                if (value != null)
                {
                    // Some headers must go on Content, others on Request
                    if (!request.Headers.TryAddWithoutValidation(name, value))
                    {
                        // Will be added to content headers if there's a body
                    }
                }
            }
        }

        // Body
        var body = options.GetProperty("body");
        if (body != null && body is not Undefined)
        {
            HttpContent content;

            if (body is string stringBody)
            {
                content = new StringContent(stringBody, Encoding.UTF8);

                // Set content-type if specified in headers
                if (options.GetProperty("headers") is ScriptObject hdrs &&
                    hdrs.GetProperty("Content-Type") is string contentType)
                {
                    content.Headers.ContentType = System.Net.Http.Headers.MediaTypeHeaderValue.Parse(contentType);
                }
            }
            else if (body is ScriptObject scriptObj)
            {
                // Assume JSON for objects
                var json = Newtonsoft.Json.JsonConvert.SerializeObject(Helper.ScriptObjectToDictionary(scriptObj));
                content = new StringContent(json, Encoding.UTF8, "application/json");
            }
            else
            {
                content = new StringContent(body.ToString() ?? "", Encoding.UTF8);
            }

            request.Content = content;
        }

        return request;
    }
}

public class Response
{
    private readonly FetchApi _origin;
    private readonly HttpResponseMessage _native_response;
    public readonly bool ok;
    public readonly int status;
    public readonly string statusText;
    internal Response(FetchApi origin, HttpResponseMessage native_response)
    {
        _origin = origin;
        _native_response = native_response;
        ok = native_response.IsSuccessStatusCode;
        status = (int)native_response.StatusCode;
        statusText = native_response.StatusCode.ToString();
    }
    public object text() => JavaScriptExtensions.ToPromise(_native_response.Content.ReadAsStringAsync(), _origin.Engine);
}