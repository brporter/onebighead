using System.ComponentModel.DataAnnotations;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.DTOs;

public class UpdateSupportStatusDto
{
    [Required]
    public SupportRequestStatus Status { get; set; }
}