using Microsoft.ClearScript;
using Microsoft.ClearScript.V8;

namespace AbyssCLI.AML2.JavaScriptAPI;
internal class Helper
{
    internal static Dictionary<string, object?>? ScriptObjectToDictionary(ScriptObject obj)
    {
        if (obj.PropertyNames == null)
            return null;

        var dict = new Dictionary<string, object?>();
        foreach (var name in obj.PropertyNames)
        {
            var value = obj.GetProperty(name);
            if (value is ScriptObject nested && value is not Undefined)
            {
                dict[name] = ScriptObjectToDictionary(nested);
            }
            else if (value is not Undefined)
            {
                dict[name] = value;
            }
        }
        return dict;
    }
    internal static Dictionary<string, string> ScriptObjectToDictionaryForceString(ScriptObject obj)
    {
        if (obj.PropertyNames == null)
            return [];

        var dict = new Dictionary<string, string>();
        foreach (var name in obj.PropertyNames)
        {
            var value = obj.GetProperty(name);
            if (value is string str_value)
            {
                dict[name] = str_value;
            }
            else
            {
                dict[name] = value.ToString() ?? "";
            }
        }
        return dict;
    }
    internal static string StringyfyJsObject(object? any)
    {
        if (any == null)
            return "";

        if (any is Undefined)
            return "";

        if (any is ScriptObject so)
            return Newtonsoft.Json.JsonConvert.SerializeObject(Helper.ScriptObjectToDictionary(so));

        return any.ToString() ?? "";
    }
}