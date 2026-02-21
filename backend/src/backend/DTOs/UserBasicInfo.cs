namespace OneBigHead.Server.DTOs;

/// <summary>
/// Basic user information for admin transfer selection.
/// </summary>
public class UserBasicInfo
{
    public int UserId { get; set; }
    public string Email { get; set; } = string.Empty;
}