using Google.Protobuf.WellKnownTypes;
using System.Net;

namespace AbyssCLI.AbyssHttp;

public static class HttpHelpers
{
    public static HttpResponseMessage TranslateResponse
    (
        HttpRequestMessage request,
        AbyssLibB.HttpResponse response,
        CookieContainer cookie_container,
        Version version
    )
    {
        byte[] bodyBytes = response!.ReadAllBody();
        var httpResponse = new HttpResponseMessage((HttpStatusCode)response.StatusCode)
        {
            Content = new ByteArrayContent(bodyBytes),
            RequestMessage = request,
            Version = version
        };

        // Parse headers and extract cookies
        string all_headers = response.GetAllHeaders();
        ParseHeader(httpResponse, all_headers, cookie_container, request.RequestUri!);
        return httpResponse;
    }

	/// <summary>
	/// Parses raw HTTP headers and adds them to the HttpResponseMessage.
	/// Optionally extracts Set-Cookie headers into a CookieContainer.
	/// </summary>
	/// <param name="response">The HttpResponseMessage to add headers to</param>
	/// <param name="all_headers">Raw HTTP response headers (newline-separated)</param>
	/// <param name="cookie_container">Optional CookieContainer to store cookies in</param>
	/// <param name="request_uri">URI of the request (required if cookie_container is provided)</param>
	public static void ParseHeader(
		HttpResponseMessage response, 
		string all_headers,
		CookieContainer cookie_container,
		Uri request_uri)
	{
        var lines = all_headers.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		foreach (var line in lines)
		{
			int colon_index = line.IndexOf(':');
			if (colon_index > 0)
			{
				string header_name = line[..colon_index].Trim();
				string header_value = line[(colon_index + 1)..].Trim();

				if (header_name.Length == 0 || header_value.Length == 0)
					continue;

                // Try response headers first. If fails, try content headers
                if (!response.Headers.TryAddWithoutValidation(header_name, header_value))
                {
                    _ = response.Content.Headers.TryAddWithoutValidation(header_name, header_value);
                }

                // Handle Set-Cookie headers if cookie container provided
                if (header_name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                {
                    if (TryParseSetCookieHeader(header_value, request_uri, out var cookie))
                    {
                        cookie_container.Add(cookie);
                    }
                }
            }
		}
	}

	/// <summary>
	/// Parses a single Set-Cookie header value into a Cookie object.
	/// Implements basic RFC 6265 parsing logic.
	/// </summary>
	/// <param name="set_cookie_value">The value of the Set-Cookie header</param>
	/// <param name="request_uri">The URI of the request that generated this cookie</param>
	/// <returns>Parsed Cookie object or null if parsing fails</returns>
	private static bool TryParseSetCookieHeader(string set_cookie_value, Uri request_uri, out Cookie cookie)
    {
        cookie = new();

        // Expected format:
        // Set-Cookie: <cookie-name>=<cookie-value>; Expires=<date>; Secure; HttpOnly
        string[] parts = set_cookie_value.Split(';', StringSplitOptions.TrimEntries);
		if (parts.Length == 0)
			return false;

        // <cookie-name>=<cookie-value>
        string[] name_value = parts[0].Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
        if (name_value.Length != 2)
            return false;

		cookie.Name = name_value[0];
		cookie.Value = name_value[1];

		// Default domain and path from request URI
		cookie.Domain = request_uri.Host;
		cookie.Path = "/";

		// Parse cookie attributes (Domain, Path, Expires, Max-Age, Secure, HttpOnly, SameSite)
		foreach (string attr in parts.Skip(1))
        {
            string[] attr_name_value = attr.Split('=', 2, StringSplitOptions.RemoveEmptyEntries);
            if (attr_name_value.Length == 0)
                continue;

            var attr_name = attr_name_value[0].ToLowerInvariant();
            string? attr_value = attr_name_value.Length == 1 ? null : attr_name_value[1];

            switch (attr_name)
            {
                case "domain":
                    if (attr_value != null) cookie.Domain = attr_value;
                    break;

                case "path":
                    if (attr_value != null) cookie.Path = attr_value;
                    break;

                case "expires":
                    if (DateTime.TryParse(attr_value, out DateTime expires))
                        cookie.Expires = expires;
                    break;

                case "max-age":
                    if (int.TryParse(attr_value, out int max_age_seconds))
                        cookie.Expires = DateTime.Now.AddSeconds(max_age_seconds);
                    break;

                case "secure":
                    cookie.Secure = true;
                    break;

                case "httponly":
                    cookie.HttpOnly = true;
                    break;
            }
        }
		return true;
	}
}
