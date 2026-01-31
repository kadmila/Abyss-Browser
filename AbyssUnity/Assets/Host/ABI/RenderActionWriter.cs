
#region Designer generated code
using Google.Protobuf;
using System;
using System.CodeDom.Compiler;

namespace AbyssCLI.ABI
{
    [GeneratedCodeAttribute("RenderActionGen", "1.0.0")]
	public class RenderActionWriter
	{
        private readonly System.IO.Stream _stream;
        public bool AutoFlush = false;
        public RenderActionWriter(System.IO.Stream stream)
        {
            _stream = stream;
        }
        private void Write(RenderAction msg)
        {
            var msg_len = msg.CalculateSize();

            lock (_stream)
            {
                _stream.Write(BitConverter.GetBytes(msg_len));
                msg.WriteTo(_stream);

            }
            if (AutoFlush)
            {
                _stream.Flush();
            }
        }
		
		public void ConsolePrint
		(
			string text
		)
		{
			var action = new RenderAction
			{
				ConsolePrint = new()
				{
					Text = text
				}
			};
			
			Write(action);
		}
		public void CreateElement
		(
			int parent_id,
			int element_id,
			ElementTag tag
		)
		{
			var action = new RenderAction
			{
				CreateElement = new()
				{
					ParentId = parent_id,
                    ElementId = element_id,
                    Tag = tag
				}
			};
			
			Write(action);
		}
		public void MoveElement
		(
			int element_id,
			int new_parent_id
		)
		{
			var action = new RenderAction
			{
				MoveElement = new()
				{
					ElementId = element_id,
                    NewParentId = new_parent_id
				}
			};
			
			Write(action);
		}
		public void DeleteElement
		(
			int element_id
		)
		{
			var action = new RenderAction
			{
				DeleteElement = new()
				{
					ElementId = element_id
				}
			};
			
			Write(action);
		}
		public void ElemSetActive
		(
			int element_id,
			bool active
		)
		{
			var action = new RenderAction
			{
				ElemSetActive = new()
				{
					ElementId = element_id,
                    Active = active
				}
			};
			
			Write(action);
		}
		public void ElemSetTransform
		(
			int element_id,
			Vec3 pos,
			Vec4 rot
		)
		{
			var action = new RenderAction
			{
				ElemSetTransform = new()
				{
					ElementId = element_id,
                    Pos = pos,
                    Rot = rot
				}
			};
			
			Write(action);
		}
		public void ElemAttachResource
		(
			int element_id,
			int resource_id,
			ResourceRole role
		)
		{
			var action = new RenderAction
			{
				ElemAttachResource = new()
				{
					ElementId = element_id,
                    ResourceId = resource_id,
                    Role = role
				}
			};
			
			Write(action);
		}
		public void ElemDetachResource
		(
			int element_id,
			int resource_id
		)
		{
			var action = new RenderAction
			{
				ElemDetachResource = new()
				{
					ElementId = element_id,
                    ResourceId = resource_id
				}
			};
			
			Write(action);
		}
		public void ElemSetValueF
		(
			int element_id,
			ValueRole role,
			float value
		)
		{
			var action = new RenderAction
			{
				ElemSetValueF = new()
				{
					ElementId = element_id,
                    Role = role,
                    Value = value
				}
			};
			
			Write(action);
		}
		public void CreateItem
		(
			int element_id,
			string sharer_hash,
			ByteString uuid
		)
		{
			var action = new RenderAction
			{
				CreateItem = new()
				{
					ElementId = element_id,
                    SharerHash = sharer_hash,
                    Uuid = uuid
				}
			};
			
			Write(action);
		}
		public void DeleteItem
		(
			int element_id
		)
		{
			var action = new RenderAction
			{
				DeleteItem = new()
				{
					ElementId = element_id
				}
			};
			
			Write(action);
		}
		public void ItemSetTitle
		(
			int element_id,
			string title
		)
		{
			var action = new RenderAction
			{
				ItemSetTitle = new()
				{
					ElementId = element_id,
                    Title = title
				}
			};
			
			Write(action);
		}
		public void ItemSetIcon
		(
			int element_id,
			int resource_id
		)
		{
			var action = new RenderAction
			{
				ItemSetIcon = new()
				{
					ElementId = element_id,
                    ResourceId = resource_id
				}
			};
			
			Write(action);
		}
		public void ItemSetActive
		(
			int element_id,
			bool active
		)
		{
			var action = new RenderAction
			{
				ItemSetActive = new()
				{
					ElementId = element_id,
                    Active = active
				}
			};
			
			Write(action);
		}
		public void ItemAlert
		(
			int element_id,
			string alert_msg
		)
		{
			var action = new RenderAction
			{
				ItemAlert = new()
				{
					ElementId = element_id,
                    AlertMsg = alert_msg
				}
			};
			
			Write(action);
		}
		public void OpenStaticResource
		(
			int resource_id,
			MIME mime,
			string file_name
		)
		{
			var action = new RenderAction
			{
				OpenStaticResource = new()
				{
					ResourceId = resource_id,
                    Mime = mime,
                    FileName = file_name
				}
			};
			
			Write(action);
		}
		public void CreateCompositeResource
		(
			int resource_id,
			int base_resource_id,
			ResourceComponent[] components
		)
		{
			var action = new RenderAction
			{
				CreateCompositeResource = new()
				{
					ResourceId = resource_id,
                    BaseResourceId = base_resource_id
				}
			};
			action.CreateCompositeResource.Components.Add( components );
			Write(action);
		}
		public void CloseResource
		(
			int resource_id
		)
		{
			var action = new RenderAction
			{
				CloseResource = new()
				{
					ResourceId = resource_id
				}
			};
			
			Write(action);
		}
		public void MemberInfo
		(
			string peer_hash
		)
		{
			var action = new RenderAction
			{
				MemberInfo = new()
				{
					PeerHash = peer_hash
				}
			};
			
			Write(action);
		}
		public void MemberSetProfile
		(
			int image_id
		)
		{
			var action = new RenderAction
			{
				MemberSetProfile = new()
				{
					ImageId = image_id
				}
			};
			
			Write(action);
		}
		public void MemberLeave
		(
			string peer_hash
		)
		{
			var action = new RenderAction
			{
				MemberLeave = new()
				{
					PeerHash = peer_hash
				}
			};
			
			Write(action);
		}
		public void LocalInfo
		(
			string aurl,
			string local_hash
		)
		{
			var action = new RenderAction
			{
				LocalInfo = new()
				{
					Aurl = aurl,
                    LocalHash = local_hash
				}
			};
			
			Write(action);
		}
		public void InfoContentShared
		(
			string content_uuid,
			string content_url,
			string sharer_hash,
			string world_uuid
		)
		{
			var action = new RenderAction
			{
				InfoContentShared = new()
				{
					ContentUuid = content_uuid,
                    ContentUrl = content_url,
                    SharerHash = sharer_hash,
                    WorldUuid = world_uuid
				}
			};
			
			Write(action);
		}
		public void InfoContentDeleted
		(
			string content_uuid,
			string sharer_hash,
			string world_uuid
		)
		{
			var action = new RenderAction
			{
				InfoContentDeleted = new()
				{
					ContentUuid = content_uuid,
                    SharerHash = sharer_hash,
                    WorldUuid = world_uuid
				}
			};
			
			Write(action);
		}
		public void PeerConnected
		(
			string peer_id
		)
		{
			var action = new RenderAction
			{
				PeerConnected = new()
				{
					PeerId = peer_id
				}
			};
			
			Write(action);
		}
		public void PeerDisconnected
		(
			string peer_id
		)
		{
			var action = new RenderAction
			{
				PeerDisconnected = new()
				{
					PeerId = peer_id
				}
			};
			
			Write(action);
		}
		public void PeerFound
		(
			string peer_id
		)
		{
			var action = new RenderAction
			{
				PeerFound = new()
				{
					PeerId = peer_id
				}
			};
			
			Write(action);
		}
		public void PeerForgot
		(
			string peer_id
		)
		{
			var action = new RenderAction
			{
				PeerForgot = new()
				{
					PeerId = peer_id
				}
			};
			
			Write(action);
		}
	}
}
#endregion Designer generated code
