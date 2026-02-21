using System.Text.Json;

namespace OneBigHead.Server.Services.Seeding;

/// <summary>
/// Helper class for JSON value conversion.
/// </summary>
public static class JsonValueConverter
{
    /// <summary>
    /// Converts a JsonElement to its native .NET type.
    /// </summary>
    public static object? ConvertJsonElement(object? value)
    {
        if (value is JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => element.GetString(),
                JsonValueKind.Number => element.TryGetInt32(out var i) ? i :
                    element.TryGetInt64(out var l) ? l :
                    element.GetDouble(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                JsonValueKind.Null => null,
                _ => element.ToString()
            };
        }
        return value;
    }
}