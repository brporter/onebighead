namespace OneBigHead.Server.DTOs;

/// <summary>
/// Result of a user account deletion operation.
/// </summary>
public class DeleteUserResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}