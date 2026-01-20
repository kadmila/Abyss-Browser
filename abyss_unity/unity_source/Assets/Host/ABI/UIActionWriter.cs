
#region Designer generated code
using Google.Protobuf;
using System;
using System.CodeDom.Compiler;

namespace AbyssCLI.ABI
{
    [GeneratedCodeAttribute("UIActionGen", "1.0.0")]
	public class UIActionWriter
	{
        private readonly System.IO.Stream _stream;
        public bool AutoFlush = false;
        public UIActionWriter(System.IO.Stream stream)
        {
            _stream = stream;
        }
        private void Write(UIAction msg)
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
		
		public void Init
		(
			ByteString root_key,
			string name
		)
		{
			var action = new UIAction
			{
				Init = new()
				{
					RootKey = root_key,
                    Name = name
				}
			};
			
			Write(action);
		}
		public void Kill
		(
			int code
		)
		{
			var action = new UIAction
			{
				Kill = new()
				{
					Code = code
				}
			};
			
			Write(action);
		}
		public void MoveWorld
		(
			string world_url
		)
		{
			var action = new UIAction
			{
				MoveWorld = new()
				{
					WorldUrl = world_url
				}
			};
			
			Write(action);
		}
		public void ShareContent
		(
			ByteString uuid,
			string url,
			Vec3 pos,
			Vec4 rot
		)
		{
			var action = new UIAction
			{
				ShareContent = new()
				{
					Uuid = uuid,
                    Url = url,
                    Pos = pos,
                    Rot = rot
				}
			};
			
			Write(action);
		}
		public void UnshareContent
		(
			ByteString uuid
		)
		{
			var action = new UIAction
			{
				UnshareContent = new()
				{
					Uuid = uuid
				}
			};
			
			Write(action);
		}
		public void ConsoleInput
		(
			int element_id,
			string text
		)
		{
			var action = new UIAction
			{
				ConsoleInput = new()
				{
					ElementId = element_id,
                    Text = text
				}
			};
			
			Write(action);
		}
	}
}
#endregion Designer generated code
