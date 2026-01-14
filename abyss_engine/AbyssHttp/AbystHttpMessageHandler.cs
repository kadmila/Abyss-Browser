using System.Net;
using System.Net.Http.Headers;

namespace AbyssCLI.AbyssHttp;
public class AbystHttpMessageHandler : HttpMessageHandler
{
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
        AbyssLibB.Error? abyst_err;
        switch (request.Method.Method)
        {
        case "GET":
            (response, abyst_err) = await Client.Client.AbystClient.Get(peerId, path);
            break;
        default:
            return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed)
            {
                Content = new StringContent($"Unsupported Method: {request.Method.Method}"),
                RequestMessage = request
            };
        }
        if (abyst_err != null)
        {
            return new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent($"Internal error: {abyst_err.Message}"),
                RequestMessage = request
            };
        }

        // Convert AbyssLibB.HttpResponse to System.Net.Http.HttpResponseMessage
        var httpResponse = new HttpResponseMessage((HttpStatusCode)response!.StatusCode)
        {
            RequestMessage = request
        };
        byte[] bodyBytes = response.ReadAllBody();
        httpResponse.Content = new ByteArrayContent(bodyBytes);

		// Sets header - requires httpResponse.Content.
		string all_headers = response.GetAllHeaders();
		if (!string.IsNullOrEmpty(all_headers))
		{
			HttpHeaderHelpers.ParseAndAddHeaders(httpResponse, all_headers);
		}

		response.Dispose();
		return httpResponse;
	}
}