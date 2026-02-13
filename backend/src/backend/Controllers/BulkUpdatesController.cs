using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.BulkUpdate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class BulkUpdatesController : ApiControllerBase
{
    private readonly IBulkUpdateQueue _queue;
    private readonly IPropertyDiffService _diffService;
    private readonly IItemRepository _itemRepository;

    public BulkUpdatesController(
        IBulkUpdateQueue queue,
        IPropertyDiffService diffService,
        IItemRepository itemRepository)
    {
        _queue = queue;
        _diffService = diffService;
        _itemRepository = itemRepository;
    }

    [HttpPost("preview")]
    public async Task<ActionResult<BulkUpdatePreviewResponse>> Preview(BulkUpdatePreviewRequest request)
    {
        var workspaceId = GetWorkspaceId();

        if (!TryParseScope(request.Scope, out var scope))
        {
            return BadRequest("Invalid scope. Must be 'template', 'category', or 'collection'.");
        }

        var count = await GetAffectedCountAsync(scope, request, workspaceId);

        // Subtract the excluded item if it would be in the count
        if (request.ExcludeItemId.HasValue && count > 0)
        {
            count = Math.Max(0, count - 1);
        }

        return Ok(new BulkUpdatePreviewResponse { AffectedItemCount = count });
    }

    [HttpPost]
    public ActionResult<BulkUpdateJobResponse> Enqueue(EnqueueBulkUpdateRequest request)
    {
        var workspaceId = GetWorkspaceId();

        if (!TryParseScope(request.Scope, out var scope))
        {
            return BadRequest("Invalid scope. Must be 'template', 'category', or 'collection'.");
        }

        var oldProps = request.OldProperties
            .Select(p => new PropertyIdentifier(p.Category, p.Name))
            .ToList();

        var newProps = request.NewProperties
            .Select(p => new PropertyIdentifier(p.Category, p.Name))
            .ToList();

        var renameMappings = request.RenameMappings?
            .Select(m => new PropertyRenameMapping(m.OldCategory, m.OldName, m.NewCategory, m.NewName))
            .ToList();

        var diff = _diffService.ComputeDiff(oldProps, newProps, renameMappings);

        var job = new BulkUpdateJob
        {
            WorkspaceId = workspaceId,
            Scope = scope,
            TemplateKey = request.TemplateKey,
            CategoryId = request.CategoryId,
            CollectionId = request.CollectionId,
            Diff = diff,
            NewPropertyOrder = newProps,
            ExcludeItemId = request.ExcludeItemId,
        };

        _queue.Enqueue(job);

        return StatusCode(StatusCodes.Status202Accepted, ToResponse(job));
    }

    [HttpGet("{jobId:guid}")]
    public ActionResult<BulkUpdateJobResponse> GetStatus(Guid jobId)
    {
        var workspaceId = GetWorkspaceId();
        var job = _queue.GetJob(jobId, workspaceId);

        if (job is null)
        {
            return NotFound();
        }

        return Ok(ToResponse(job));
    }

    [HttpGet("collection/{collectionId:int}/status")]
    public ActionResult<BulkUpdateJobResponse> GetCollectionStatus(int collectionId)
    {
        var workspaceId = GetWorkspaceId();
        var job = _queue.GetActiveJobForCollection(collectionId, workspaceId);

        if (job is null)
        {
            return NoContent();
        }

        return Ok(ToResponse(job));
    }

    private static bool TryParseScope(string scope, out BulkUpdateScope result)
    {
        return Enum.TryParse(scope, ignoreCase: true, out result) &&
               Enum.IsDefined(result);
    }

    private async Task<int> GetAffectedCountAsync(
        BulkUpdateScope scope, BulkUpdatePreviewRequest request, int workspaceId)
    {
        return scope switch
        {
            BulkUpdateScope.Template when request.TemplateKey.HasValue =>
                await _itemRepository.CountByTemplateKeyAsync(request.TemplateKey.Value, workspaceId),
            BulkUpdateScope.Category when request.CategoryId.HasValue =>
                await _itemRepository.CountByCategoryIdAsync(request.CategoryId.Value, workspaceId),
            BulkUpdateScope.Collection when request.CollectionId.HasValue =>
                await _itemRepository.CountByCollectionIdAsync(request.CollectionId.Value, workspaceId),
            _ => 0
        };
    }

    private static BulkUpdateJobResponse ToResponse(BulkUpdateJob job)
    {
        return new BulkUpdateJobResponse
        {
            JobId = job.JobId,
            Status = job.Status.ToString(),
            TotalItems = job.TotalItems,
            ProcessedItems = job.ProcessedItems,
            FailedItems = job.FailedItems,
            ErrorMessage = job.ErrorMessage,
        };
    }
}
