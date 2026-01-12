#nullable enable
#pragma warning disable IDE1006 //naming convension
namespace AbyssCLI.AML.JavaScriptAPI;
public class Host
{
	public string aurl => "abyss://" + Client.Client.Host.ID;
	public string id => Client.Client.Host.ID;
	public string idCert => Client.Client.Host.RootCertificate;
	public string hsKeyCert => Client.Client.Host.GetHandshakeKeyCertificate();
	public void register(string id_cert, string hs_key_cert)
	{
		var result = Client.Client.Host.AppendKnownPeer(
			System.Text.Encoding.UTF8.GetBytes(id_cert), 
			System.Text.Encoding.UTF8.GetBytes(hs_key_cert));
		if (result != null)
		{
			Client.Client.RenderWriter.ConsolePrint("register failed: " + result.Message);
		}
	}
	public void connect(string peerId)
	{
		var result = Client.Client.Host.Dial(peerId);
		if (result != null)
		{
			Client.Client.RenderWriter.ConsolePrint("connect failed: " + result.Message);
		}
	}
	public void move_world(string aurl)
	{
		_ = Client.Client.IssueMoveWorldInternalRequest(aurl);
	}
}
