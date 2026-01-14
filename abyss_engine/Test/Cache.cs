using CacheCow.Client;
using System.Net;
using System.Net.Http.Headers;

namespace AbyssCLI.Test;

public class Cache
{
	public static async Task TestAbystClientWithCacheCow()
	{
		try
		{
			Console.WriteLine("=== CacheCow + AbystClient Integration Test ===\n");

            var collocatedH3Handler = new AbyssHttp.CollocatedH3HttpMessageHandler();
            using var httpClient = ClientExtensions.CreateClient(collocatedH3Handler);

            var testUrl = "https://localhost:4433/c/";

            // 1) First request - should miss cache and fetch via AbystClient
            Console.WriteLine("--- FIRST REQUEST (should fetch) ---");
            var firstResponse = await httpClient.GetAsync(testUrl);
            Console.WriteLine($"First Response: {firstResponse}||");


            string firstBody = await firstResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"Body preview: {firstBody}\n");

            // 8) Second request - should retrieve from cache
            Console.WriteLine("--- SECOND REQUEST (should come from cache) ---");
            var secondResponse = await httpClient.GetAsync(testUrl);
            Console.WriteLine($"Second Response: {secondResponse}||");

            string secondBody = await secondResponse.Content.ReadAsStringAsync();
            Console.WriteLine($"Body preview: {secondBody}\n");

            // 9) Verify caching behavior
            Console.WriteLine("--- VERIFICATION ---");
            bool bodiesMatch = firstBody == secondBody;
            Console.WriteLine($"Response bodies match: {bodiesMatch}");

            Console.WriteLine("\n=== Test completed successfully ===");
        }

        catch (Exception ex)
		{
			Console.WriteLine("Cache test failed: " + ex.ToString());
			Environment.Exit(1);
		}
	}
}
