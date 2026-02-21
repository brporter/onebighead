using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

public class PropertySuggestion
{
    [Key]
    public int Id { get; set; }

    public int WorkspaceId { get; set; }

    public int CollectionId { get; set; }

    public PropertySuggestionType Type { get; set; }

    [Required]
    [MaxLength(200)]
    public string Value { get; set; } = string.Empty;

    [JsonIgnore]
    [ForeignKey(nameof(WorkspaceId))]
    public Workspace? Workspace { get; set; }

    [JsonIgnore]
    [ForeignKey(nameof(CollectionId))]
    public Collection? Collection { get; set; }
}
