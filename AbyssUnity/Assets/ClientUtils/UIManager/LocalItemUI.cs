using System;
using UnityEditor;
using UnityEngine;
using UnityEngine.UIElements;

namespace ClientUtils.UIManager
{
    internal class LocalItemUI
    {
        public readonly VisualElement VisualElement;
        public LocalItemUI(VisualTreeAsset VisualTree, Action ItemCloseCallback)
        {
            VisualElement = VisualTree.CloneTree();
            VisualElement.Q<Button>("local-item-close-button").clicked += ItemCloseCallback;
        }
        public void SetIcon(Texture2D image)
        {
            VisualElement.style.backgroundImage = image;
        }
    }
}
