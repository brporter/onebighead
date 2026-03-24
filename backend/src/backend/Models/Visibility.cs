using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum Visibility
{
    Private = 1,
    Public = 2,
}
