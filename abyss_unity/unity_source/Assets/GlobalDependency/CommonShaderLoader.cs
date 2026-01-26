using System.Collections.Generic;
using System.Reflection;
using UnityEngine;
using static Google.Protobuf.Compiler.CodeGeneratorResponse.Types;

namespace GlobalDependency
{
    public class CommonShaderLoader : MonoBehaviour //actually, material
    {
        public UnityEngine.Material none;
        public UnityEngine.Material color;
        public UnityEngine.Material diffuse;

        //public UnityEngine.Material pbr;
        //public Shader specular;
        //public Shader bsdf;
        //public Shader transparent;
        //public Shader translucent;

        Dictionary<string, UnityEngine.Material> _rumtime_map;
        Dictionary<string, Dictionary<string, int>> _parameter_id_maps;

        void OnEnable()
        {
            _rumtime_map = new();
            _parameter_id_maps = new();

            FieldInfo[] fields = this.GetType().GetFields(BindingFlags.Public | BindingFlags.Instance);
            foreach (FieldInfo field in fields)
            {
                if (field.FieldType == typeof(UnityEngine.Material))
                {
                    //add material to _runtime_map, indexed by the variable name
                    var mat = field.GetValue(this) as UnityEngine.Material;
                    _rumtime_map[field.Name] = mat;

                    var id_map = new Dictionary<string, int>();
                    for (int i = 0; i < mat.shader.GetPropertyCount(); i++)
                    {
                        //iterate parameters, get property name id, add to id_map if the name matches.
                        string propertyName = mat.shader.GetPropertyName(i);
                        int propertyID = mat.shader.GetPropertyNameId(i);
                        Debug.Log($"ShaderLoader: {field.Name} ({i}) - Name: {propertyName} - Property ID: {propertyID}");
                        id_map[propertyName] = propertyID;
                    }
                    _parameter_id_maps[field.Name] = id_map;
                }
            }
        }
        void OnDisable()
        {
            _parameter_id_maps = null;
            _rumtime_map = null;
        }
        public UnityEngine.Material Get(string name)
        {
            if (_rumtime_map.TryGetValue(name, out Material mat))
                return mat;

            return none;
        }
        public void SetMaterialTexture(Material target, string mat_name, string param_name, Texture2D texture)
        {
            var id = _parameter_id_maps[mat_name][param_name];
            target.SetTexture(id, texture);
        }
        public void ClearMaterialTexture(Material target, string mat_name, string param_name)
        {
            var id = _parameter_id_maps[mat_name][param_name];
            target.SetTexture(id, new Texture2D(2, 2));
        }
    }
}
