using AbyssCLI.ABI;
using System;
using System.IO;

namespace EngineCom
{
    public class RenderActionReader
    {
        private readonly BinaryReader _reader;
        public RenderActionReader(Stream stream)
        {
            _reader = new(stream);
        }

        public RenderAction Read()
        {
            int length = _reader.ReadInt32();
            if (length <= 0)
                throw new Exception("invalid length message");

            byte[] data = _reader.ReadBytes(length);
            return RenderAction.Parser.ParseFrom(data);
        }
    }
}