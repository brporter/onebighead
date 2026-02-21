namespace OneBigHead.Server.DTOs;

/// <summary>
/// Result of an admin transfer operation.
/// </summary>
public class TransferAdminResponse
{
    public bool Success { get; set; }
    public string? Error { get; set; }
}