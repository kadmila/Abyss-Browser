using System.Numerics;

namespace AbyssCLI.Client;

public class World : IDisposable
{
    public Guid WSID; // set when WorldEnter event arrives

    private readonly AbyssLibB.Host _host;
	private readonly AbyssLibB.World _world;
	private HL.ContentB? _environment;
	private readonly Dictionary<string, HL.Member> _members = []; //peer ID - Member
	private readonly Dictionary<Guid, HL.Item> _local_items = []; //UUID - item
	private readonly object _lock = new();
	private bool _active = true;

	public World(AbyssLibB.Host host, AbyssLibB.World world)
	{
		_host = host;
		_world = world;
		WSID = world.WSID;
	}

    public void ShareItem(Guid uuid, string url, float[] transform)
	{
		var item = new HL.Item(_host.ID, uuid, url,
			new(transform[0], transform[1], transform[2]),
			new(transform[4], transform[5], transform[6], transform[3]));

		lock (_lock)
		{
			_local_items[uuid] = item;
			
			// Convert members to targets for ObjectAppend
			var targets = _members.Select(m => (m.Value.Peer!, m.Value.PeerWSID)).ToArray();
			if (targets.Length > 0)
			{
				var objectInfo = new AbyssLibB.ObjectInfo
				{
					Id = uuid,
					Address = url,
					Transform = transform
				};
				_world.ObjectAppend(targets, [objectInfo]);
			}
		}
	}

	public void UnshareItem(Guid item_id)
	{
		lock (_lock)
		{
			HL.Item item = _local_items[item_id];
			item.Dispose();
			_ = _local_items.Remove(item_id);
			
			// Convert members to targets for ObjectDelete
			var targets = _members.Select(m => (m.Value.Peer!, m.Value.PeerWSID)).ToArray();
			if (targets.Length > 0)
			{
				_world.ObjectDelete(targets, [item_id]);
			}
		}
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
    }
	public void OnMemberRequest(AbyssLibB.ESessionRequest evnt)
	{
		Client.Cerr.WriteLine($"OnMemberRequest from {evnt.PeerID}");
		_world.AcceptSession(evnt.PeerID, evnt.PeerWSID);
	}
	public void OnMemberReady(AbyssLibB.ESessionReady evnt)
	{
		Client.Cerr.WriteLine($"OnMemberReady: {evnt.PeerID}");
		lock (_lock)
		{
			// Note: In AbyssLibB, we don't have a Peer handle from session events
			// We'll need to track peers separately when EPeerConnected events arrive
			// For now, create a placeholder member
			if (!_members.TryAdd(evnt.PeerID, new HL.Member(evnt.PeerID, evnt.PeerWSID)))
			{
				Client.Cerr.WriteLine("failed to append peer; old peer session pends");
				return;
			}
			Client.RenderWriter.MemberInfo(evnt.PeerID);

			static float[] PosRotSerialize(Vector3 pos, Quaternion rot) =>
				[pos.X, pos.Y, pos.Z, rot.W, rot.X, rot.Y, rot.Z];

			// Send all local items to the new member
			if (_local_items.Count > 0)
			{
				var objectInfos = _local_items.Select(kvp => new AbyssLibB.ObjectInfo
				{
					Id = kvp.Key,
					Address = kvp.Value._url.ToString(),
					Transform = PosRotSerialize(
						kvp.Value._content.Document.Metadata.pos.Native,
						kvp.Value._content.Document.Metadata.rot.Native
					)
				}).ToArray();
				
				// We need the Peer handle - we'll get it from EPeerConnected event
				// For now, skip sending objects until we have the peer handle
			}
		}
	}
	public void OnMemberObjectAppend(AbyssLibB.EObjectAppend evnt)
	{
		Client.Cerr.WriteLine($"OnMemberObjectAppend from {evnt.PeerID}");

		lock (_lock)
		{
			if (!_members.TryGetValue(evnt.PeerID, out HL.Member? member))
			{
				Client.Cerr.WriteLine("failed to find member");
				return;
			}

			foreach (var obj in evnt.Objects)
			{
				Client.Cerr.WriteLine("member object: " + obj.Address);
				var item = new HL.Item(evnt.PeerID, obj.Id, obj.Address,
					new(obj.Transform[0], obj.Transform[1], obj.Transform[2]),
					new(obj.Transform[4], obj.Transform[5], obj.Transform[6], obj.Transform[3]));
				if (!member.remote_items.TryAdd(obj.Id, item))
				{
					Client.Cerr.WriteLine("uid collision of objects appended from peer");
					continue;
				}
			}
		}
	}
	public void OnMemberObjectDelete(AbyssLibB.EObjectDelete evnt)
	{
		Client.Cerr.WriteLine($"OnMemberObjectDelete from {evnt.PeerID}");
		lock (_lock)
		{
			if (!_members.TryGetValue(evnt.PeerID, out HL.Member? member))
			{
				Client.Cerr.WriteLine("failed to find member");
				return;
			}

			foreach (Guid id in evnt.ObjectIDs)
			{
				if (!member.remote_items.Remove(id, out HL.Item? item))
				{
					Client.Cerr.WriteLine("peer tried to delete unshared objects");
					continue;
				}
				item.Dispose();
			}
		}
	}
	public void OnMemberLeave(string peerID)
	{
		Client.Cerr.WriteLine($"OnMemberLeave: {peerID}");
		lock (_lock)
		{
			if (!_members.Remove(peerID, out HL.Member? value))
			{
				Client.Cerr.WriteLine("non-existing peer leaved");
				return;
			}
			Client.RenderWriter.MemberLeave(peerID);

			foreach (HL.Item item in value.remote_items.Values)
			{
				item.Dispose();
			}
		}
    }
	public bool TryExecuteJavascript(string javascript)
    {
		if (_environment == null)
			return false;
		return _environment.Document.TryEnqueueJavaScript("<console>", javascript);
    }

    public void Dispose()
    {
        _active = false;
        _environment?.Dispose();
        _world.Dispose();

        foreach (KeyValuePair<string, HL.Member> member in _members)
        {
            foreach (HL.Item item in member.Value.remote_items.Values)
            {
                item.Dispose();
            }
        }
        foreach (HL.Item item in _local_items.Values)
        {
            item.Dispose();
        }
        _members.Clear();
        _local_items.Clear();

		GC.SuppressFinalize(this);
    }
	~World()
    {
        Client.Cerr.WriteLine("Warning:::World must be manually disposed. This is a bug");
        Dispose();
    }
}
