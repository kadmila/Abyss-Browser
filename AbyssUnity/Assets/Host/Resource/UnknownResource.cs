
namespace Host
{
    class UnknownResource : StaticResource
    {
        public readonly MIME Mime;
        public UnknownResource(string file_name, MIME mime) : base(file_name)
        {
            Mime = mime;
        }
        public override void Init() { }
        public override void UpdateMMFRead() { }
        public override void Dispose()
        {
            base.Dispose();
        }
    }
}