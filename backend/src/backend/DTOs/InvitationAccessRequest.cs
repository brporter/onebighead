using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public sealed class InvitationAccessRequest
{
    public Guid InvitationId { get; set; }
    [Required, StringLength(64, MinimumLength = 64)]
    public string Token { get; set; } = string.Empty;
}
