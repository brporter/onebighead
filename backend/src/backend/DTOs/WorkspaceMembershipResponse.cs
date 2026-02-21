using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class WorkspaceMembershipResponse
{
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
    public WorkspaceRole WorkspaceRole { get; set; }
    public bool HasCompletedWelcome { get; set; }
}