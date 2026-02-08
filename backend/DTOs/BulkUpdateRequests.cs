using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class PropertyIdentifierDto
{
    [Required]
    public string Category { get; set; } = string.Empty;

    [Required]
    public string Name { get; set; } = string.Empty;
}

public class PropertyRenameMappingDto
{
    [Required]
    public string OldCategory { get; set; } = string.Empty;

    [Required]
    public string OldName { get; set; } = string.Empty;

    [Required]
    public string NewCategory { get; set; } = string.Empty;

    [Required]
    public string NewName { get; set; } = string.Empty;
}

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

public class BulkUpdatePreviewRequest
{
    [Required]
    public string Scope { get; set; } = string.Empty;

    public Guid? TemplateKey { get; set; }
    public int? CategoryId { get; set; }
    public int? CollectionId { get; set; }
    public int? ExcludeItemId { get; set; }
}

public class BulkUpdatePreviewResponse
{
    public int AffectedItemCount { get; set; }
}

public class BulkUpdateJobResponse
{
    public Guid JobId { get; set; }
    public string Status { get; set; } = string.Empty;
    public int TotalItems { get; set; }
    public int ProcessedItems { get; set; }
    public int FailedItems { get; set; }
    public string? ErrorMessage { get; set; }
}
