using backend.Data;
using backend.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ThemesController : ControllerBase
{
    private readonly IThemeRepository _themeRepository;

    public ThemesController(IThemeRepository themeRepository)
    {
        _themeRepository = themeRepository;
    }

    /// <summary>
    /// Gets all available collection themes.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<CollectionThemeDto>>> GetThemes()
    {
        var themes = await _themeRepository.GetAllAsync();
        var response = themes.Select(CollectionThemeDto.FromEntity);
        return Ok(response);
    }

    /// <summary>
    /// Gets a specific collection theme by ID.
    /// </summary>
    [HttpGet("{id}")]
    public async Task<ActionResult<CollectionThemeDto>> GetTheme(int id)
    {
        var theme = await _themeRepository.GetByIdAsync(id);
        if (theme is null)
        {
            return NotFound();
        }
        return Ok(CollectionThemeDto.FromEntity(theme));
    }
}
