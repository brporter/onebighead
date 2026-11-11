using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace OneBigHead.Server.Models;

/// <summary>A pending access grant. Email is a delivery label, never an account identifier.</summary>
public sealed class WorkspaceInvitation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public int WorkspaceId { get; set; }
    public Workspace Workspace { get; set; } = null!;
    [MaxLength(320)] public string Email { get; set; } = string.Empty;
    public WorkspaceRole Role { get; set; }
    [JsonIgnore, MaxLength(64)] public string TokenHash { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public int? AcceptedByUserId { get; set; }
}
