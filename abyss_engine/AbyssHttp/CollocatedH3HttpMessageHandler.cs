using System.Net;

namespace AbyssCLI.AbyssHttp;

/// <summary>
/// HTTP message handler for collocated HTTP/3 requests using native AbyssLibB client.
/// Supports cookie sharing with standard HttpClient through a shared CookieContainer.
/// </summary>
public class CollocatedH3HttpMessageHandler : HttpMessageHandler
{
	private readonly AbyssLibB.CollocatedH3Client _collocated_h3_client;
	private readonly CookieContainer _cookie_container;

	public CollocatedH3HttpMessageHandler(
		AbyssLibB.CollocatedH3Client collocated_h3_client,
		CookieContainer cookie_container)
	{
		_collocated_h3_client = collocated_h3_client;
		_cookie_container = cookie_container;
	}
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Client.Client.Cerr.WriteLine("this is fucked up");
        var task = SendAsync(request, cancellationToken);
        task.Wait(CancellationToken.None);
        return task.Result; 
    }
	protected override async Task<HttpResponseMessage> SendAsync(
		HttpRequestMessage request,
		CancellationToken cancellationToken)
	{
        //Client.Client.Cerr.WriteLine($"request: {request}||");

        // Check if this is an https:// URL
        if (request.RequestUri?.Scheme != "https")
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Unsupported scheme: {request.RequestUri?.Scheme}"),
                RequestMessage = request,
                Version = HttpVersion.Version30,
            };
        }

        // Use full URL string
        string url = request.RequestUri.ToString();

        // Make the request via Http3Client
        AbyssLibB.HttpResponse? response;
        AbyssLibB.AbyssLibError? http3_err;
        switch (request.Method.Method)
        {
        case "GET":
            (response, http3_err) = await _collocated_h3_client.Get(url);
            break;
        default:
            return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed)
            {
                Content = new StringContent($"Unsupported Method: {request.Method.Method}"),
                RequestMessage = request,
                Version = HttpVersion.Version30,
            };
        }
        if (http3_err != null)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Internal error: {http3_err.Message}"),
                RequestMessage = request,
                Version = HttpVersion.Version30,
            };
        }

        var httpResponse = HttpHelpers.TranslateResponse(request, response!, _cookie_container, HttpVersion.Version30);

        response!.Dispose();
        return httpResponse;
	}
}
