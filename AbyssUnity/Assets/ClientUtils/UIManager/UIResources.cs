using UnityEngine;
using UnityEngine.UIElements;

[CreateAssetMenu(fileName = "UIResources", menuName = "Scriptable Objects/UIResources")]
public class UIResources : ScriptableObject
{
    public Texture2D DefaultWorldPic;
    public Texture2D DefaultItemIcon;
    public Texture2D DefaultMemberProfile;
    public VisualTreeAsset ItemIconAsset;
}
