using Microsoft.ClearScript;

namespace AbyssCLI.AML.JavaScriptAPI
{
    internal class Helper
    {
        internal static object? ScriptObjectToDictionary(ScriptObject obj)
        {
            if (obj.PropertyNames == null) return null;

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
}
