using System.Net;
using System.Net.Http.Headers;

namespace AbyssCLI.AbyssHttp;
public class AbystHttpMessageHandler : HttpMessageHandler
{
    private readonly AbyssLibB.AbystClient _abyst_client;
    private readonly CookieContainer _cookie_container;
    public AbystHttpMessageHandler(
        AbyssLibB.AbystClient abyst_client,
        CookieContainer cookie_container)
    {
        _abyst_client = abyst_client;
        _cookie_container = cookie_container;
    }
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        // Check if this is an abyst:// URL
        if (request.RequestUri?.Scheme != "abyst")
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Unsupported scheme: {request.RequestUri?.Scheme}"),
                RequestMessage = request
            };
        }

        // Parse abyst://peer-id/path format
        string peerId = request.RequestUri.Host;
        string path = request.RequestUri.PathAndQuery;

        // Make the request via AbystClient
        AbyssLibB.HttpResponse? response;
        AbyssLibB.AbyssLibError? abyst_err;
        switch (request.Method.Method)
        {
        case "GET":
            (response, abyst_err) = await _abyst_client.Get(peerId, path);
            break;
        default:
            return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed)
            {
                Content = new StringContent($"Unsupported Method: {request.Method.Method}"),
                RequestMessage = request,
                Version = HttpVersion.Version30,
            };
        }
        if (abyst_err != null)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Internal error: {abyst_err.Message}"),
                RequestMessage = request,
                Version = HttpVersion.Version30,
            };
        }

        var httpResponse = HttpHelpers.TranslateResponse(request, response!, _cookie_container, HttpVersion.Version30);

		response!.Dispose();
		return httpResponse;
	}
}