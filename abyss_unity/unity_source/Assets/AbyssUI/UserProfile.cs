using System;
using UnityEngine.UIElements;

public class UserProfile : VisualElement
{
    public readonly string peer_hash;
    private Action OnClose;
    public UserProfile(string peer_hash)
    {
        this.peer_hash = peer_hash;
    }
    public void RegisterCloseCallback(Action callback)
    {
        OnClose = callback;
    }
}