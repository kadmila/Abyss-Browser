using AbyssCLI.HL;
using System.Collections.Generic;
using System.Numerics;

namespace AbyssCLI.Client;

// World is only accessed from Client. It is not thread safe.
public class World : IDisposable
{
    public Guid WSID; // set when WorldEnter event arrives

    private readonly AbyssLibB.Host _host;
	private readonly AbyssLibB.World _world;
	private HL.Content? _environment;
	private readonly Dictionary<string, Member> _members = []; //peer ids - WSID
	private readonly Dictionary<Guid, HL.Item> _local_items = []; //UUID - item

	public World(AbyssLibB.Host host, AbyssLibB.World world)
	{
		_host = host;
		_world = world;
		WSID = world.WSID;
	}

    public void ShareItem(Guid uuid, string url, float[] transform)
	{
		var item = new HL.Item(_host.ID, uuid, url, transform);
        _local_items[uuid] = item;

		if (_members.Count == 0)
			return;

        // Convert members to targets for ObjectAppend
        var targets = _members.Values.Select(m => (m.PeerId, m.WSID)).ToArray();
        _world.ObjectAppend(targets, [item.SerializedObjectInfo]);
    }

	public void UnshareItem(Guid item_id)
    {
        HL.Item item = _local_items[item_id];
        item.Dispose();
        _ = _local_items.Remove(item_id);

        if (_members.Count == 0)
            return;

        // Convert members to targets for ObjectDelete
        var targets = _members.Values.Select(m => (m.PeerId, m.WSID)).ToArray();
        _world.ObjectDelete(targets, [item_id]);
    }

	//internals
	public void OnWorldEnter(AbyssLibB.EWorldEnter evnt)
    {
        Client.Cerr.WriteLine($"OnWorldEnter: {evnt.URL}");
		var metadata = new AML.AmlMetadata()
		{
			title = evnt.URL.ToString()
		};
        _environment = new(evnt.URL, metadata);

		// expose world except for the empty world.
		if (evnt.URL == "")
            return;

        var expose_err = Client.Host.ExposeWorldForJoin(_world, "/");
        if (expose_err != null)
		{
			Client.Cerr.WriteLine("failed to expose the world: " + expose_err.Message);
		}
    }
	public void OnMemberRequest(AbyssLibB.ESessionRequest evnt)
	{
		Client.Cerr.WriteLine($"OnMemberRequest from {evnt.PeerID}");
		_world.AcceptSession(evnt.PeerID, evnt.PeerWSID);
	}
	public void OnMemberReady(AbyssLibB.ESessionReady evnt)
	{
		Client.Cerr.WriteLine($"OnMemberReady: {evnt.PeerID}");
		_members[evnt.PeerID] = new Member(evnt.PeerID, evnt.PeerWSID);
        Client.RenderWriter.MemberInfo(evnt.PeerID);

		if (_local_items.Count == 0)
			return;

        var targets = _members.Values.Select(m => (m.PeerId, m.WSID)).ToArray();
        _world.ObjectAppend(targets, [.. _local_items.Values.Select(e => e.SerializedObjectInfo)]);
    }
	public void OnMemberObjectAppend(AbyssLibB.EObjectAppend evnt)
	{
		Client.Cerr.WriteLine($"OnMemberObjectAppend from {evnt.PeerID}");
        if (!_members.TryGetValue(evnt.PeerID, out var member))
        {
            Client.Cerr.WriteLine("failed to find member");
            return;
        }

		var items = evnt.Objects.Select(e => new HL.Item(evnt.PeerID, e.Id, e.Address, e.Transform));
        foreach (var item in items)
        {
			if (!member.RemoteItems.TryAdd(item.UUID, item))
			{
                // destroy items that failed to add. - this is a failure of remote peer, should never happen.
                Client.Cerr.WriteLine("warning: item id collided, discarding colliding item");
                item.Dispose();
			}
        }
	}
	public void OnMemberObjectDelete(AbyssLibB.EObjectDelete evnt)
	{
		Client.Cerr.WriteLine($"OnMemberObjectDelete from {evnt.PeerID}");
        if (!_members.TryGetValue(evnt.PeerID, out var member))
        {
            Client.Cerr.WriteLine("failed to find member");
            return;
        }

        foreach (var object_id in evnt.ObjectIDs)
        {
            if (!member.RemoteItems.Remove(object_id, out var item))
            {
                Client.Cerr.WriteLine("warning: tried to delete nonexisting item");
                continue;
            }
            item.Dispose();
        }
	}
	public void OnMemberLeave(string peerID)
	{
		Client.Cerr.WriteLine($"OnMemberLeave: {peerID}");
        if (!_members.Remove(peerID, out var member))
        {
            Client.Cerr.WriteLine("fatal:::nonexisting member leave. This is AND bug");
            return;
        }
        member.Dispose();
        Client.RenderWriter.MemberLeave(peerID);
    }
	public bool TryExecuteJavascript(string javascript)
    {
		if (_environment == null)
			return false;
		return _environment.Document.TryRunScript("<console>", javascript);
    }

    public void Dispose()
    {
        _environment?.Dispose();
        _world.Dispose();

        foreach (var member in _members.Values)
        {
            member.Dispose();
        }
        foreach (var item in _local_items.Values)
        {
            item.Dispose();
        }

		GC.SuppressFinalize(this);
    }
	~World()
    {
        Client.Cerr.WriteLine("Warning:::World must be manually disposed. This is a bug");
        Dispose();
    }
}
