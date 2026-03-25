using System.Text;
using static AbyssCLI.AbyssLibB;

namespace AbyssCLI.Test
{
    public class Basics
    {
        public static async Task Test()
        {
            try
            {
                // 1) Initialize library
                _ = AbyssLibB.Initialize();

                // 2) Create host from testkey.pem
                string pemPath = "testkey.pem";
                if (!File.Exists(pemPath))
                {
                    Console.WriteLine($"Error: {pemPath} not found in project root directory");
                    Environment.Exit(1);
                }

                byte[] keyBytes = File.ReadAllBytes(pemPath);

                var (host, hostError) = AbyssLibB.Host.Create(keyBytes);
                if (hostError != null)
                {
                    Console.WriteLine($"Error creating host: {hostError.Message}");
                    Environment.Exit(1);
                }

                if (host == null)
                {
                    Console.WriteLine("Error: Failed to create host (unknown error)");
                    Environment.Exit(1);
                }

                using (host)
                {
                    Console.WriteLine($"Host created successfully with ID: {host.ID}");

                    var bind_error = host.Bind();
                    if (bind_error != null)
                    {
                        Console.WriteLine(bind_error.Message);
                        Environment.Exit(1);
                    }

                    host.Serve();

                    using (var abystClient = host.NewAbystClient())
                    {
                        var (response, error) = await abystClient.Get(host.ID, "path");
                        if (error != null)
                        {
                            Console.WriteLine(error.Message);
                        }
                        else
                        {
                            Console.WriteLine(response!.GetAllHeaders());
                        }
                    }

                    // 3) Create CollocatedHttp3Client from host
                    using (var http3Client = host.NewCollocatedHttp3Client())
                    {
                        var (response, error) = await http3Client.Get("https://localhost:4433");

                        if (error != null)
                        {
                            Console.WriteLine($"HTTP request failed: {error.Message}");
                            Environment.Exit(1);
                        }

                        if (response == null)
                        {
                            Console.WriteLine("HTTP request returned null response");
                            Environment.Exit(1);
                        }

                        using (response)
                        {
                            Console.WriteLine($"HTTP Response Status: {response.StatusCode}");

                            // Log headers
                            string allHeaders = response.GetAllHeaders();
                            if (!string.IsNullOrEmpty(allHeaders))
                            {
                                Console.WriteLine("Response Headers:");
                                Console.WriteLine(allHeaders);
                            }

                            // Log body
                            byte[] bodyBytes = response.ReadAllBody();
                            if (bodyBytes.Length > 0)
                            {
                                string bodyText = System.Text.Encoding.UTF8.GetString(bodyBytes);
                                Console.WriteLine($"Response Body ({bodyBytes.Length} bytes):");
                                Console.WriteLine(bodyText);
                            }
                            else
                            {
                                Console.WriteLine("Response Body: (empty)");
                            }

                            Console.WriteLine("HTTP request completed successfully");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            Environment.Exit(0);
        }

        public static async Task TestObjectAppend()
        {
            try
            {
                // 1) Initialize library
                _ = AbyssLibB.Initialize();

                // 2) Create host from testkey.pem
                string pemPath = "testkey.pem";
                string pemPath2 = "testkey2.pem";

                byte[] keyBytes = File.ReadAllBytes(pemPath);
                byte[] keyBytes2 = File.ReadAllBytes(pemPath2);

                var (host, _) = AbyssLibB.Host.Create(keyBytes);
                var (host2, _) = AbyssLibB.Host.Create(keyBytes2);

                using (host)
                using (host2)
                {
                    host!.Bind();
                    host.Serve();

                    host2!.Bind();
                    host2.Serve();

                    host.AppendKnownPeer(Encoding.UTF8.GetBytes(host2.RootCertificate), Encoding.UTF8.GetBytes(host2.GetHandshakeKeyCertificate()));
                    host2.AppendKnownPeer(Encoding.UTF8.GetBytes(host.RootCertificate), Encoding.UTF8.GetBytes(host.GetHandshakeKeyCertificate()));

                    // consume PeerFound events
                    host.WaitForEvent();
                    host2.WaitForEvent();

                    var host_task = Task.Run(() =>
                    {
                        var (world, error_wo) = host.OpenWorld("https://world.com");
                        if (error_wo != null)
                        {
                            Console.WriteLine(error_wo);
                            Environment.Exit(1);
                        }
                        host.ExposeWorldForJoin(world!, "/");

                        var (evnt, evnt_error) = host.WaitForEvent();
                        if (evnt_error != null)
                        {
                            Console.WriteLine(evnt_error);
                            Environment.Exit(1);
                        }
                        if (evnt is not EWorldEnter)
                        {
                            Console.WriteLine("invalid event object");
                            Environment.Exit(1);
                        }
                        var e_we = evnt as EWorldEnter;
                        Console.WriteLine("Opened world: " + e_we!.URL);

                        var error = host.Dial(host2.ID);
                        if (error != null)
                        {
                            Console.WriteLine(error);
                            Environment.Exit(1);
                        }

                        (evnt, evnt_error) = host.WaitForEvent();
                        var e_pc = evnt as EPeerConnected;

                        (evnt, evnt_error) = host.WaitForEvent();
                        var e_srd = evnt as ESessionReady;

                        (evnt, evnt_error) = host.WaitForEvent();
                        var e_oa = evnt as EObjectAppend;

                        Console.WriteLine(e_oa!.Objects[0].Address);
                    });

                    var host2_task = Task.Run(() =>
                    {
                        var (evnt, evnt_error) = host2.WaitForEvent();
                        if (evnt_error != null)
                        {
                            Console.WriteLine(evnt_error);
                            Environment.Exit(1);
                        }
                        if (evnt is not EPeerConnected)
                        {
                            Console.WriteLine("invalid event object");
                            Environment.Exit(1);
                        }
                        var e_pc = evnt as EPeerConnected;

                        var (world, join_error) = host2.JoinWorld(e_pc!.PeerID, "/");
                        (evnt, evnt_error) = host2.WaitForEvent();
                        var e_we = evnt as EWorldEnter;

                        (evnt, evnt_error) = host2.WaitForEvent();
                        var e_srd = evnt as ESessionReady;

                        var obj = new ObjectInfo()
                        {
                            Id = Guid.NewGuid(),
                            Transform = [1, 2, 3, 4, 5, 6, 7, 8],
                            Address = "https://some-object.com",
                        };
                        world!.ObjectAppend([(e_pc.PeerID, e_srd!.PeerWSID)], [obj]);
                    });

                    await host_task;
                    await host2_task;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            Environment.Exit(0);
        }
    }
}
