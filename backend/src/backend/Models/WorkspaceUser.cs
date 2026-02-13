using System.ComponentModel.DataAnnotations.Schema;

namespace OneBigHead.Server.Models;

public class WorkspaceUser
{
    public int UserId { get; set; }
    public int WorkspaceId { get; set; }
    public WorkspaceRole WorkspaceRole { get; set; } = WorkspaceRole.Normal;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [ForeignKey(nameof(UserId))]
    public User User { get; set; } = null!;

    [ForeignKey(nameof(WorkspaceId))]
    public Workspace Workspace { get; set; } = null!;
}
