using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class CreateSupportReplyDto
{
    [Required]
    [MaxLength(4000)]
    public string Message { get; set; } = string.Empty;
}