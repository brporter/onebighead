using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class EnqueueBulkUpdateRequest
{
    [Required]
    public string Scope { get; set; } = string.Empty;

    public Guid? TemplateKey { get; set; }
    public int? CategoryId { get; set; }
    public int? CollectionId { get; set; }
    public int? ExcludeItemId { get; set; }

    [Required]
    public List<PropertyIdentifierDto> OldProperties { get; set; } = new();

    [Required]
    public List<PropertyIdentifierDto> NewProperties { get; set; } = new();

    public List<PropertyRenameMappingDto>? RenameMappings { get; set; }
}