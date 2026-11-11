using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CompleteWelcomeRequest
{
    [MaxLength(200)]
    public string? WorkspaceName { get; set; }

    /// <summary>Omit to finish welcome without creating an initial collection.</summary>
    public SetupCollectionRequest? Collection { get; set; }
}
