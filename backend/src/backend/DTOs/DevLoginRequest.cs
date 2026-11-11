using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

#if DEBUG
public class DevLoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}
#endif
