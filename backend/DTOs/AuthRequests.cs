using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CompleteWelcomeRequest
{
    [MaxLength(200)]
    public string? WorkspaceName { get; set; }
}

public class AuthCallbackRequest
{
    public string Token { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
}

public class AuthCallbackResponse
{
    public bool Success { get; set; }
    public string Email { get; set; } = string.Empty;
    public int WorkspaceId { get; set; }
    public string WorkspaceName { get; set; } = string.Empty;
}

#if DEBUG
public class DevLoginRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}
#endif
