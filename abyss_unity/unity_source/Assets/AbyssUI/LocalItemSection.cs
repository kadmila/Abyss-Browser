using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

public class LocalItemSection
{
    [HideInInspector] public readonly VisualElement IconContainerVE;
    public Action<Guid> OnCloseCallback;

    private readonly Dictionary<int, ItemIcon> _items;
    private readonly Texture2D _default_icon;
    public LocalItemSection(VisualElement visual_element, Texture2D default_icon)
    {
        IconContainerVE = visual_element;
        _items = new();
        _default_icon = default_icon;
    }
    public void AddItem(int element_id, Guid uuid)
    {
        var item = new ItemIcon(uuid, _default_icon)
        {
            OnClose = OnCloseCallback,
        };
        _items[element_id] = item;
        IconContainerVE.Add(item);
    }
    public bool TryRemoveItem(int element_id)
    {
        if (_items.Remove(element_id, out var old))
        {
            old.RemoveFromHierarchy();
            return true;
        }
        else
        {
            return false;
        }
    }
    public bool TryUpdateIcon(int element_id, Texture2D icon)
    {
        if(_items.TryGetValue(element_id, out var item))
        {
            item.style.backgroundImage = icon;
            return true;
        }
        else
        {
            return false;
        }
    }
}