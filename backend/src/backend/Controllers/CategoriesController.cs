using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class CategoriesController(ICategoryReadService reads, ICategoryWriteService writes) : ApiControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<CategoryResponse>>> GetCategories([FromQuery] int? collectionId = null)
    {
        var categories = await reads.GetAllAsync(GetWorkspaceId(), collectionId);
        return categories is null ? NotFound("Collection not found") : Ok(categories);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<CategoryResponse>> GetCategory(int id)
    {
        var category = await reads.GetByIdAsync(id, GetWorkspaceId());
        return category is null ? NotFound() : Ok(category);
    }

    [HttpGet("{id}/templates")]
    public async Task<ActionResult<IEnumerable<int>>> GetCategoryTemplates(int id)
    {
        var templates = await reads.GetInheritedTemplateIdsAsync(id, GetWorkspaceId());
        return templates is null ? NotFound() : Ok(templates);
    }

    [HttpPost]
    public async Task<ActionResult<CategoryResponse>> CreateCategory(CreateCategoryRequest request, CancellationToken cancellationToken = default)
    {
        var result = await writes.CreateAsync(GetWorkspaceId(), request, cancellationToken);
        if (result.Error is { } error) return Failure(error);
        return CreatedAtAction(nameof(GetCategory), new { id = result.Value!.CategoryId }, result.Value);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<CategoryResponse>> UpdateCategory(int id, UpdateCategoryRequest request, CancellationToken cancellationToken = default)
    {
        var result = await writes.UpdateAsync(id, GetWorkspaceId(), request, cancellationToken);
        return result.Error is { } error ? Failure(error) : Ok(result.Value);
    }

    [HttpPut("reorder")]
    public async Task<ActionResult<IEnumerable<CategoryResponse>>> ReorderCategories(ReorderCategoriesRequest request, CancellationToken cancellationToken = default)
    {
        var workspaceId = GetWorkspaceId();
        var result = await writes.ReorderAsync(workspaceId, request, cancellationToken);
        if (result.Error is { } error) return Failure(error);
        var categories = await reads.GetAllAsync(workspaceId, result.Value);
        return categories is null ? NotFound("Collection not found") : Ok(categories);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteCategory(int id, CancellationToken cancellationToken = default)
    {
        var result = await writes.DeleteAsync(id, GetWorkspaceId(), cancellationToken);
        return result.Error is { } error ? Failure(error) : NoContent();
    }

    private ActionResult Failure(CategoryWriteError error) => error.Kind switch
    {
        CategoryWriteFailure.Invalid => BadRequest(error.Message),
        CategoryWriteFailure.NotFound => NotFound(error.Message),
        CategoryWriteFailure.Forbidden => StatusCode(StatusCodes.Status403Forbidden, error.Message),
        CategoryWriteFailure.Conflict => Conflict(error.Message),
        _ => throw new ArgumentOutOfRangeException(nameof(error))
    };
}
