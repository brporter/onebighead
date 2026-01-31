using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Visibility
{
    Default = 0,  // Inherit from parent (replaces null)
    Private = 1,  // Explicitly private (replaces false)
    Public = 2    // Explicitly public (replaces true)
}
