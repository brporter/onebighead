using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CompleteWelcomeRequest
{
    [MaxLength(200)]
    public string? WorkspaceName { get; set; }
}

#if DEBUG
#endif
