using System.ComponentModel.DataAnnotations;

namespace backend.DTOs;

public class CompleteWelcomeRequest
{
    [MaxLength(200)]
    public string? TenantName { get; set; }
}
