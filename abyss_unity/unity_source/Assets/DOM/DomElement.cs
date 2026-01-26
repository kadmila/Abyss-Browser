using GlobalDependency;
using Host;
using System;
using System.Collections.Generic;

#nullable enable
namespace DOM
{
    public abstract class DomElement : IDisposable
    {
        public readonly int ElementId;
        private DomElement? _parent;
        private readonly List<DomElement> _children = new();

        private readonly Dictionary<int, (StaticResource, ResourceRole)> _attached_resource_roles = new();
        private readonly Dictionary<ResourceRole, (int, StaticResource)> _occupied_roles = new();

        public DomElement(int element_id)
        {
            ElementId = element_id;
        }
        public abstract T? GetThing<T>() where T : class;
        public void SetParent(DomElement parent)
        {
            _ = _parent?._children.Remove(this);
            _parent?.AfterRemovingChild(this);

            parent._children.Add(this);
            parent.AfterAppendingChild(this);

            _parent = parent;
        }
        protected abstract void AfterRemovingChild(DomElement child);
        protected abstract void AfterAppendingChild(DomElement child);
        public void AttachResource(int resource_id, StaticResource resource, ResourceRole role)
        {
            bool is_replacing = false;

            if (_occupied_roles.Remove(role, out var old_entry))
            {
                _ = _attached_resource_roles.Remove(old_entry.Item1);
                is_replacing = true;
            }
            _occupied_roles[role] = (resource_id, resource);

            if (!_attached_resource_roles.TryAdd(resource_id, (resource, role)))
                throw new Exception("fatal:::duplicate resource on same element");

            if (is_replacing)
                ResourceReplacingCallback(role, resource);
            else
                ResourceAttachingCallback(role, resource);
        }
        public void DetachResource(int resource_id)
        {
            if (!_attached_resource_roles.Remove(resource_id, out var value))
                throw new Exception("fatal:::detaching non-existing resource");
            if (!_occupied_roles.Remove(value.Item2))
                throw new Exception("fatal:::_occupied_roles corrupted");

            ResourceDetachingCallback(value.Item2);
        }
        protected abstract void ResourceAttachingCallback(ResourceRole role, StaticResource resource);
        protected abstract void ResourceReplacingCallback(ResourceRole role, StaticResource resource);
        protected abstract void ResourceDetachingCallback(ResourceRole role);
        public virtual void SetValueF(ValueRole role, float value) => throw new NotImplementedException();

        public virtual void Dispose()
        {
            _parent = null;
            foreach (var child in _children)
                child.Dispose();
        }
    }
}