using Host;
using System;
using UnityEngine;

#nullable enable
namespace DOM
{
    public sealed class Pbrm : DomElement
    {
        private readonly ClientUtils.RenderingPrimitives.MaterialLoader MaterialLoader = ClientUtils.ClientUtils.GetInstance().MaterialLoader;

        public readonly Material Material;
        public Pbrm(int element_id) : base(element_id)
        {
            Material = new(MaterialLoader.Get("color"));
        }

        public override T? GetThing<T>() where T : class
        {
            object? result = typeof(T) switch
            {
                var t when t == typeof(Material) => Material,
                _ => null
            };
            return (T?)result;
        }
        protected override void AfterAppendingChild(DomElement child) => throw new System.NotImplementedException();
        protected override void AfterRemovingChild(DomElement child) => throw new System.NotImplementedException();
        protected override void ResourceAttachingCallback(ResourceRole role, StaticResource resource)
        {
            MaterialLoader.SetMaterialTexture(Material, "color", role switch
            {
                ResourceRole.Albedo => "_MainTex",
                _ => throw new InvalidOperationException("unexpected resource role"),
            }, (resource as Image)!.Texture);
        }
        protected override void ResourceReplacingCallback(ResourceRole role, StaticResource resource) =>
            ResourceAttachingCallback(role, resource);
        protected override void ResourceDetachingCallback(ResourceRole role)
        {
            MaterialLoader.ClearMaterialTexture(Material, "color", role switch
            {
                ResourceRole.Albedo => "_MainTex",
                _ => throw new InvalidOperationException("unexpected resource role"),
            });
        }
        public override void Dispose()
        {
            base.Dispose();
            UnityEngine.Object.Destroy(Material);
        }
    }
}