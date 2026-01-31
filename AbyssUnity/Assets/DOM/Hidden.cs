using Host;
using UnityEngine;

#nullable enable
namespace DOM
{
    public sealed class Hidden : DomElement
    {
        public readonly GameObject GameObject;
        public Hidden(int element_id) : base(element_id)
        {
            GameObject = new GameObject(element_id.ToString());
        }
        public override T? GetThing<T>() where T : class
        {
            object? result = typeof(T) switch
            {
                var t when t == typeof(GameObject) => GameObject,
                _ => null
            };
            return (T?)result;
        }
        protected override void AfterAppendingChild(DomElement child)
        {
            child.GetThing<GameObject>()?.transform.SetParent(GameObject.transform, false);
            //switch (child)
            //{
            //case O o:
            //    break;
            //case Obj obj:
            //    break;
            //case Pbrm pbrm:
            //    break;
            //default:
            //    break;
            //}
        }
        protected override void AfterRemovingChild(DomElement child)
        {
        }
        protected override void ResourceAttachingCallback(ResourceRole role, StaticResource resource)
             => throw new System.NotImplementedException(); //this is impossible on O (For now)
        protected override void ResourceReplacingCallback(ResourceRole role, StaticResource resource)
             => throw new System.NotImplementedException(); //this is impossible on O (For now)
        protected override void ResourceDetachingCallback(ResourceRole role)
             => throw new System.NotImplementedException(); //this is impossible on O (For now)
        public override void Dispose()
        {
            base.Dispose();
            Object.Destroy(GameObject);
        }
    }
}