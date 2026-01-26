using AbyssCLI.ABI;
using DOM;
using System;
using System.Reflection;
using System.Text;
using UnityEngine;

namespace Host
{
    partial class Host
    {
        // LogRequest is very slow; must be excluded in release build.
        private void LogRequest(RenderAction render_action)
        {
            var type = render_action.GetType();
            var prop = type.GetProperty(
                render_action.InnerCase.ToString(),
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic
            );
            var inner_action = prop.GetValue(render_action);
            GlobalDependency.Logger.Writer.WriteLine(FormatFlatLogLine(inner_action));
        }
        string FormatFlatLogLine(object obj)
        {
            var sb = new StringBuilder();
            //_ = sb.Append($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {obj.GetType().Name} |");
            _ = sb.Append($"{obj.GetType().Name} |");

            var type = obj.GetType();
            var fields = type.GetFields(BindingFlags.Instance | BindingFlags.Public);
            var properties = type.GetProperties(BindingFlags.Instance | BindingFlags.Public);

            foreach (var field in fields)
            {
                if (!IsSimple(field.FieldType)) continue;
                _ = sb.Append($" {field.Name}={FormatValue(field.GetValue(obj))}");
            }

            foreach (var prop in properties)
            {
                if (!prop.CanRead || !IsSimple(prop.PropertyType)) continue;
                _ = sb.Append($" {prop.Name}={FormatValue(prop.GetValue(obj))}");
            }

            return sb.ToString();
        }
        bool IsSimple(Type type)
        {
            return type.IsPrimitive || type == typeof(string) || type == typeof(byte[]);
        }

        string FormatValue(object value)
        {
            if (value == null) return "null";

            return value switch
            {
                string s => s,
                byte[] bytes => BitConverter.ToString(bytes).Replace("-", ""), // Hex string
                bool b => b ? "true" : "false",
                float f => f.ToString("R"),
                double d => d.ToString("R"),
                _ => value.ToString()
            };
        }
    }
}