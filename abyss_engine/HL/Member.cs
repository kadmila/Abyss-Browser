namespace AbyssCLI.HL;

internal class Member
{
	public string PeerID { get; }
	public Guid PeerWSID { get; }
	public AbyssLibB.Peer? Peer { get; set; } // Set when EPeerConnected event arrives
	public readonly Dictionary<Guid, HL.Item> remote_items = [];
	
	public Member(string peerID, Guid peerWSID)
	{
		PeerID = peerID;
		PeerWSID = peerWSID;
		Peer = null;
	}
}
