using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Models;

/// <summary>Retains a creation identity even after its workspace or collection is deleted.</summary>
public sealed class WorkspaceSetupReceipt
{
    public int UserId { get; set; }
    public Guid RequestId { get; set; }
    [MaxLength(64)]
    public string RequestHash { get; set; } = string.Empty;
    public int? WorkspaceId { get; set; }
    public int? CollectionId { get; set; }
    public DateTime CreatedAt { get; set; }
}
