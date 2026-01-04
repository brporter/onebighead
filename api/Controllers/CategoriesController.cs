using api.Models;
using Microsoft.AspNetCore.Mvc;

namespace api.Controllers;

[ApiController]
[Route("[controller]")]
public class CategoriesController : ControllerBase
{
    private static readonly Category[] SampleCategories =
    [
        new(1, 1, "Motorola 68000 Computers", "Some Description", null),
        new(2, 1, "Compact Macintosh", "Some description", 1),
        new(3, 1, "Apple II", "Some description", 1),
        new(4, 1, "Peripherals", "Some description", null),
        new(5, 1, "Monitors", "Some description", 4),
        new(6, 1, "Printers", "Some description", 4),
        new(7, 1, "Intel Computers", "Some description", null)
    ];

    [HttpGet]
    public ActionResult<Category[]> GetCategories()
    {
        return SampleCategories;
    }
}

