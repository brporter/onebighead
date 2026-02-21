using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class BulkUpdatePreviewRequest
{
    [Required]
    public string Scope { get; set; } = string.Empty;

    public Guid? TemplateKey { get; set; }
    public int? CategoryId { get; set; }
    public int? CollectionId { get; set; }
    public int? ExcludeItemId { get; set; }
}