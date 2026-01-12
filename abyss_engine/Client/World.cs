using AbyssCLI.Tool;
using System.Numerics;

namespace AbyssCLI.Client;

public class World
{
	private readonly AbyssLibB.Host _host;
	private readonly AbyssLibB.World _world;
	private Guid _worldSessionId; // Not readonly - will be set when WorldEnter event arrives
	internal readonly HL.ContentB _environment;
	private readonly Dictionary<string, HL.Member> _members = []; //peer ID - Member
	private readonly Dictionary<Guid, HL.Item> _local_items = []; //UUID - item
	private readonly object _lock = new();
	private bool _active = true;

	public World(AbyssLibB.Host host, AbyssLibB.World world, AbyssURL URL)
	{
		_host = host;
		_world = world;
		_worldSessionId = Guid.Empty; // Will be set when we receive WorldEnter event
		_environment = new(URL, new()
		{
			title = URL.ToString()
		});
	}
	
	// Called by Client event loop when event is for this world
	public void HandleEvent(dynamic evnt)
	{
		if (!_active) return;
		
		switch (evnt)
		{
		case AbyssLibB.EWorldEnter worldEnter:
			_worldSessionId = worldEnter.WSID;
			break;
		case AbyssLibB.ESessionRequest sessionRequest:
			if (sessionRequest.WSID == _worldSessionId)
				OnMemberRequest(sessionRequest);
			break;
		case AbyssLibB.ESessionReady sessionReady:
			if (sessionReady.WSID == _worldSessionId)
				OnMemberReady(sessionReady);
			break;
		case AbyssLibB.ESessionClose sessionClose:
			if (sessionClose.WSID == _worldSessionId)
				OnMemberLeave(sessionClose.PeerID);
			break;
		case AbyssLibB.EObjectAppend objectAppend:
			if (objectAppend.WSID == _worldSessionId)
				OnMemberObjectAppend(objectAppend);
			break;
		case AbyssLibB.EObjectDelete objectDelete:
			if (objectDelete.WSID == _worldSessionId)
				OnMemberObjectDelete(objectDelete);
			break;
		case AbyssLibB.EWorldLeave worldLeave:
			if (worldLeave.WSID == _worldSessionId)
			{
				Client.CerrWriteLine($"World leave: code={worldLeave.Code}, msg={worldLeave.Message}");
				_active = false;
			}
			break;
		}
	}

	public void ShareItem(Guid uuid, AbyssURL url, float[] transform)
	{
		var item = new HL.Item(_host.ID, uuid, url,
			new(transform[0], transform[1], transform[2]),
			new(transform[4], transform[5], transform[6], transform[3]));

		lock (_lock)
		{
			_local_items[uuid] = item;
			
			// Convert members to targets for ObjectAppend
			var targets = _members.Select(m => (m.Value.Peer, m.Value.PeerWSID)).ToArray();
			if (targets.Length > 0)
			{
				var objectInfo = new AbyssLibB.ObjectInfo
				{
					Id = uuid,
					Address = url.Raw,
					Transform = transform
				};
				_world.ObjectAppend(targets, [objectInfo]);
			}
		}
	}

	public void UnshareItem(Guid guid)
	{
		lock (_lock)
		{
			HL.Item item = _local_items[guid];
			item.Stop();
			_ = _local_items.Remove(guid);
			
			// Convert members to targets for ObjectDelete
			var targets = _members.Select(m => (m.Value.Peer, m.Value.PeerWSID)).ToArray();
			if (targets.Length > 0)
			{
				_world.ObjectDelete(targets, [guid]);
			}
		}
	}

	public void Leave()
	{
		_active = false;
		_environment.Dispose();
		_world.Dispose();

		foreach (KeyValuePair<string, HL.Member> member in _members)
		{
			foreach (HL.Item item in member.Value.remote_items.Values)
			{
				item.Stop();
			}
		}
		foreach (HL.Item item in _local_items.Values)
		{
			item.Stop();
		}
		_members.Clear();
		_local_items.Clear();
	}

	//internals
	private void OnMemberRequest(AbyssLibB.ESessionRequest evnt)
	{
		Client.CerrWriteLine($"OnMemberRequest from {evnt.PeerID}");
		_world.AcceptSession(evnt.PeerID, evnt.PeerWSID);
	}
	
	private void OnMemberReady(AbyssLibB.ESessionReady evnt)
	{
		Client.CerrWriteLine($"OnMemberReady: {evnt.PeerID}");
		lock (_lock)
		{
			// Note: In AbyssLibB, we don't have a Peer handle from session events
			// We'll need to track peers separately when EPeerConnected events arrive
			// For now, create a placeholder member
			if (!_members.TryAdd(evnt.PeerID, new HL.Member(evnt.PeerID, evnt.PeerWSID)))
			{
				Client.CerrWriteLine("failed to append peer; old peer session pends");
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

	private void OnMemberObjectAppend(AbyssLibB.EObjectAppend evnt)
	{
		Client.CerrWriteLine($"OnMemberObjectAppend from {evnt.PeerID}");

		lock (_lock)
		{
			if (!_members.TryGetValue(evnt.PeerID, out HL.Member? member))
			{
				Client.CerrWriteLine("failed to find member");
				return;
			}

			foreach (var obj in evnt.Objects)
			{
				if (!AbyssURLParser.TryParse(obj.Address, out AbyssURL? abyss_url))
				{
					Client.CerrWriteLine("failed to parse object url: " + obj.Address);
					continue;
				}
				
				Client.CerrWriteLine("member object: " + abyss_url.ToString());
				var item = new HL.Item(evnt.PeerID, obj.Id, abyss_url,
					new(obj.Transform[0], obj.Transform[1], obj.Transform[2]),
					new(obj.Transform[4], obj.Transform[5], obj.Transform[6], obj.Transform[3]));
				if (!member.remote_items.TryAdd(obj.Id, item))
				{
					Client.CerrWriteLine("uid collision of objects appended from peer");
					continue;
				}
			}
		}
	}
	
	private void OnMemberObjectDelete(AbyssLibB.EObjectDelete evnt)
	{
		Client.CerrWriteLine($"OnMemberObjectDelete from {evnt.PeerID}");
		lock (_lock)
		{
			if (!_members.TryGetValue(evnt.PeerID, out HL.Member? member))
			{
				Client.CerrWriteLine("failed to find member");
				return;
			}

			foreach (Guid id in evnt.ObjectIDs)
			{
				if (!member.remote_items.Remove(id, out HL.Item? item))
				{
					Client.CerrWriteLine("peer tried to delete unshared objects");
					continue;
				}
				item.Stop();
			}
		}
	}
	private void OnMemberLeave(string peerID)
	{
		Client.CerrWriteLine($"OnMemberLeave: {peerID}");
		lock (_lock)
		{
			if (!_members.Remove(peerID, out HL.Member? value))
			{
				Client.CerrWriteLine("non-existing peer leaved");
				return;
			}
			Client.RenderWriter.MemberLeave(peerID);

			foreach (HL.Item item in value.remote_items.Values)
			{
				item.Stop();
			}
		}
	}
}
