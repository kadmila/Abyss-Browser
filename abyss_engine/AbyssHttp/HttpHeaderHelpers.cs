namespace AbyssCLI.AbyssHttp;

public static class HttpHeaderHelpers
{
	public static void ParseAndAddHeaders(HttpResponseMessage response, string allHeaders)
	{
        var lines = allHeaders.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
		foreach (var line in lines)
		{
			int colonIndex = line.IndexOf(':');
			if (colonIndex > 0)
			{
				string headerName = line[..colonIndex].Trim();
				string headerValue = line[(colonIndex + 1)..].Trim();
                //Console.WriteLine($"header: |{headerName}| => |{headerValue}|");

                try
				{
					// Try response headers first
                    if (response.Headers.TryAddWithoutValidation(headerName, headerValue))
                        continue;

					// Try content headers
					_=response.Content.Headers.TryAddWithoutValidation(headerName, headerValue);
                }
				catch
				{
					// Skip headers that fail to parse
					Console.WriteLine($"[HttpHeaderHelpers] Warning: Failed to add header '{headerName}'");
				}
			}
		}
	}
}
