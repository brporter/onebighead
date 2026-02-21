using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

/// <summary>
/// Request to transfer admin role to another user.
/// </summary>
public class TransferAdminRequest
{
    [Required]
    public int NewAdminUserId { get; set; }
}