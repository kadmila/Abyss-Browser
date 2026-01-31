using System;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.UIElements;

public class MemberProfileSection
{
    public readonly VisualElement visualElement;
    private readonly Dictionary<string, Texture2D> memberProfiles;
    private readonly Texture2D defaultProfile;
    private Action<string> onClick;
    public MemberProfileSection(VisualElement visualElement, Texture2D defaultProfile)
    {
        this.visualElement = visualElement;
        this.memberProfiles = new();
    }
    public void CreateProfile(string peer_hash)
    {
        memberProfiles[peer_hash] = defaultProfile;
        Show();
    }
    public void UpdateProfile(string peer_hash, Texture2D profile)
    {
        memberProfiles[peer_hash] = profile;
        Show();
    }
    public void RemoveProfile(string peer_hash)
    {
        memberProfiles.Remove(peer_hash);
        Show();
    }
    public void Show()
    {
        visualElement.Clear();
        foreach (var entry in memberProfiles)
        {
            VisualElement profileElement = new();
            profileElement.AddToClassList("userprofile");
            profileElement.style.backgroundImage = entry.Value;
            visualElement.Add(profileElement);

            profileElement.RegisterCallback<ClickEvent>(evt =>
            {
                onClick(entry.Key);
            });
        }
    }
    public void RegisterClickCallback(Action<string> callback)
    {
        onClick = callback;
    }
}