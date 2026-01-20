#nullable enable
using Host;
using UnityEngine;

namespace DOM
{
    public sealed class Bcol : DomElement
    {
        public readonly BoxCollider BoxCollider;
        public Bcol(int element_id, Color color) : base(element_id)
        {
            BoxCollider = new();
            BoxCollider.size = new Vector3(1, 1, 1);
        }
        public override T? GetThing<T>() where T : class
        {
            object? result = typeof(T) switch
            {
                var t when t == typeof(BoxCollider) => BoxCollider,
                _ => null
            };
            return (T?)result;
        }
        protected override void AfterAppendingChild(DomElement child) => throw new System.NotImplementedException();
        protected override void AfterRemovingChild(DomElement child) => throw new System.NotImplementedException();
        protected override void ResourceAttachingCallback(ResourceRole role, StaticResource resource) => throw new System.NotImplementedException();
        protected override void ResourceReplacingCallback(ResourceRole role, StaticResource resource) => throw new System.NotImplementedException();
        protected override void ResourceDetachingCallback(ResourceRole role) => throw new System.NotImplementedException();
        public override void Dispose()
        {
            base.Dispose();
            UnityEngine.Object.Destroy(BoxCollider);
        }
    }
}