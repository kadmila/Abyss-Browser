using UnityEngine;


[CreateAssetMenu(fileName = "MaterialResources", menuName = "Scriptable Objects/MaterialResources")]
public class MaterialResources : ScriptableObject
{
    public UnityEngine.Material none;
    public UnityEngine.Material color;
    public UnityEngine.Material diffuse;

    //public UnityEngine.Material pbr;
    //public Shader specular;
    //public Shader bsdf;
    //public Shader transparent;
    //public Shader translucent;
}
