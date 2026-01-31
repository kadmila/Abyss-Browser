using Host;
using UnityEngine;

#nullable enable
namespace DOM
{
    public sealed class Obj : DomElement
    {
        public readonly GameObject GameObject;
        public bool IsGameObjectDestryRequired = false;
        public readonly MeshFilter MeshFilter;
        public readonly MeshRenderer MeshRenderer;
        public Obj(int element_id) : base(element_id)
        {
            GameObject = new GameObject(element_id.ToString());
            MeshFilter = GameObject.AddComponent<MeshFilter>();
            MeshRenderer = GameObject.AddComponent<MeshRenderer>();
        }
        public override T? GetThing<T>() where T : class
        {
            object? result = typeof(T) switch
            {
                var t when t == typeof(GameObject) => GameObject,
                var t when t == typeof(MeshFilter) => MeshFilter,
                var t when t == typeof(MeshRenderer) => MeshRenderer,
                _ => null
            };
            return (T?)result;
        }
        protected override void AfterAppendingChild(DomElement child)
        {
            MeshRenderer.material = (child as Pbrm)!.Material;
        }
        protected override void AfterRemovingChild(DomElement child)
        {
            MeshRenderer.material = null;
        }
        protected override void ResourceAttachingCallback(ResourceRole role, StaticResource resource)
        {
            if (resource is not Host.Mesh mesh)
            {
                if (resource is UnknownResource unknown_resource)
                {
                    // .GetType().GetMember(unknown_resource.Mime.ToString()).Single()
                    //    .GetCustomAttribute<Google.Protobuf.Reflection.OriginalNameAttribute>();
                    //RuntimeCout.Print("warning:::unsupported MIME type for <obj> src: " + unknown_resource.Mime.ToString());
                    return;
                }
                //RuntimeCout.Print("warning:::unexpected resource type for <obj>: " + resource.GetType().ToString());
                return;
            }
            MeshFilter.mesh = mesh.UnityMesh;
        }
        protected override void ResourceReplacingCallback(ResourceRole role, StaticResource resource) =>
            ResourceAttachingCallback(role, resource);
        protected override void ResourceDetachingCallback(ResourceRole role)
        {
            MeshFilter.mesh = null;
        }
        public override void Dispose()
        {
            base.Dispose();
            if (IsGameObjectDestryRequired)
                Object.Destroy(GameObject);
        }
    }
}