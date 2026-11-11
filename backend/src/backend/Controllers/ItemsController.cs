using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Items;
using OneBigHead.Server.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ItemsController(
    IItemReadService itemReads,
    IItemWriteService itemWrites,
    IItemViewRecorder itemViews) : ApiControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IEnumerable<Item>>> GetItems(
        [FromQuery] int? categoryId = null,
        [FromQuery] bool includeDescendants = false,
        [FromQuery][Range(0, int.MaxValue)] int? skip = null,
        [FromQuery][Range(0, int.MaxValue)] int? take = null)
    {
        var items = await itemReads.GetAllAsync(GetWorkspaceId(), categoryId, includeDescendants);
        IEnumerable<Item> page = items;
        if (skip.HasValue) page = page.Skip(skip.Value);
        if (take.HasValue) page = page.Take(take.Value);
        var result = page.ToList();
        var paginated = skip.HasValue || take.HasValue;
        if (paginated) Response.Headers["X-Total-Count"] = items.Count.ToString();

        // The validator describes this response, including pagination metadata.
        var etag = ETagHelper.ComputeETag(new { Items = result, TotalCount = paginated ? (int?)items.Count : null });
        Response.Headers.ETag = etag;
        if (Request.Headers.IfNoneMatch == etag)
        {
            return StatusCode(StatusCodes.Status304NotModified);
        }
        return Ok(result);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<Item>> GetItem(int id)
    {
        var item = await itemReads.GetByIdAsync(id, GetWorkspaceId());
        return item is null ? NotFound() : Ok(item);
    }

    [HttpPost]
    public async Task<ActionResult<Item>> CreateItem(CreateItemRequest request) =>
        WriteResponse(await itemWrites.CreateAsync(GetWorkspaceId(), request), created: true);

    [HttpPut("{id}")]
    public async Task<ActionResult<Item>> UpdateItem(int id, UpdateItemRequest request) =>
        WriteResponse(await itemWrites.UpdateAsync(GetWorkspaceId(), id, request), created: false);

    private ActionResult<Item> WriteResponse(ItemWriteResult result, bool created) => result.Status switch
    {
        ItemWriteStatus.Success => created
            ? CreatedAtAction(nameof(GetItem), new { id = result.Item!.Id }, result.Item)
            : Ok(result.Item),
        ItemWriteStatus.Invalid => BadRequest(result.Error),
        ItemWriteStatus.Conflict => Conflict(result.Error),
        _ => NotFound()
    };

    [HttpDelete("{id}")]
    public async Task<IActionResult> DeleteItem(int id) =>
        await itemWrites.DeleteAsync(GetWorkspaceId(), id) ? NoContent() : NotFound();

    [HttpPost("{id}/view")]
    public async Task<IActionResult> RecordItemView(int id)
    {
        await itemViews.RecordAsync(GetWorkspaceId(), id);
        return NoContent();
    }
}
