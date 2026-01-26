using System.Runtime.InteropServices;
using UnityEngine;

#nullable enable
namespace Host
{
    class Image : StaticResource
    {
        public UnityEngine.Texture2D? Texture;
        byte[]? _bytes;
        public Image(string file_name) : base(file_name)
        {
            _bytes = new byte[Size];
        }
        public override void Init()
        {
            Texture = new(2, 2);
        }
        public override void UpdateMMFRead()
        {
            var current_size = CurrentSize;

            if (ConsumedSize == current_size)
                return;

            _ = _accessor.ReadArray(
                Marshal.SizeOf<StaticResourceHeader>() + ConsumedSize, 
                _bytes,
                ConsumedSize,
                current_size - ConsumedSize
            );
            ConsumedSize = current_size;

            _ = Texture.LoadImage(_bytes);

            if (ConsumedSize == Size)
            {
                //completed.
                _bytes = null;
            }
        }
        public override void Dispose()
        {
            Object.Destroy(Texture);
            _bytes = null;
            base.Dispose();
        }
    }
}