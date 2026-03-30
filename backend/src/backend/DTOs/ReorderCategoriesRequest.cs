using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.DTOs;

public class ReorderCategoriesRequest
{
    [Required]
    public List<CategorySortOrderEntry> Categories { get; set; } = new();
}
