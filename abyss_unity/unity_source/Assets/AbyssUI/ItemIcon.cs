using System;
using UnityEngine;
using UnityEngine.UIElements;

public class ItemIcon : VisualElement
{
    public readonly Guid uuid;
    public Action<Guid> OnClose;
    public ItemIcon(Guid uuid, Texture2D icon)
    {
        this.uuid = uuid;
        AddToClassList("item-icon");
        style.backgroundImage = icon;

        VisualElement closeButton = new();
        closeButton.AddToClassList("item-icon-close"); // Assigns a CSS-like class tag
        Add(closeButton);

        closeButton.RegisterCallback<ClickEvent>(evt =>
        {
            OnClose(uuid);
            closeButton.RemoveFromHierarchy();
        });
    }
}