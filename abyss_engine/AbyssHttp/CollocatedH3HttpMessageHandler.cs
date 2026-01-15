using System.Net;

namespace AbyssCLI.AbyssHttp;
public class CollocatedH3HttpMessageHandler(AbyssLibB.CollocatedH3Client _collocated_h3_client) : HttpMessageHandler
{
    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Console.WriteLine("this is fucked up");
        var task = SendAsync(request, cancellationToken);
        task.Wait(CancellationToken.None);
        return task.Result; 
    }
	protected override async Task<HttpResponseMessage> SendAsync(
		HttpRequestMessage request,
		CancellationToken cancellationToken)
	{
        Console.WriteLine($"request: {request}||");

        // Check if this is an https:// URL
        if (request.RequestUri?.Scheme != "https")
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Unsupported scheme: {request.RequestUri?.Scheme}"),
                RequestMessage = request,
                //Version = HttpVersion.Version30,
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
                //Version = HttpVersion.Version30,
            };
        }
        if (http3_err != null)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Internal error: {http3_err.Message}"),
                RequestMessage = request,
                //Version = HttpVersion.Version30,
            };
        }

        // Convert AbyssLibB.HttpResponse to System.Net.Http.HttpResponseMessage
        byte[] bodyBytes = response!.ReadAllBody();
        var httpResponse = new HttpResponseMessage((HttpStatusCode)response.StatusCode)
        {
            Content = new ByteArrayContent(bodyBytes),
            RequestMessage = request,
            //Version = HttpVersion.Version30,
        };

        // Sets header - requires httpResponse.Content.
        string all_headers = response.GetAllHeaders();
        if (!string.IsNullOrEmpty(all_headers))
        {
            HttpHeaderHelpers.ParseAndAddHeaders(httpResponse, all_headers);
        }

        response.Dispose();

        Console.WriteLine($"response: {httpResponse}||");
        return httpResponse;
	}
}
