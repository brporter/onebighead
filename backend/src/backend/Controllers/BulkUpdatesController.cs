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
    private const string InvalidTargetMessage = "Choose a valid scope for the item update.";
    private readonly IBulkUpdateQueue _queue;
    private readonly IPropertyDiffService _diffService;
    private readonly IBulkUpdateTargets _targets;
    private readonly IBulkUpdateJobs _jobs;

    public BulkUpdatesController(
        IBulkUpdateQueue queue,
        IPropertyDiffService diffService,
        IBulkUpdateTargets targets,
        IBulkUpdateJobs jobs)
    {
        _queue = queue;
        _diffService = diffService;
        _targets = targets;
        _jobs = jobs;
    }

    [HttpPost("preview")]
    public async Task<ActionResult<BulkUpdatePreviewResponse>> Preview(BulkUpdatePreviewRequest request)
    {
        var workspaceId = GetWorkspaceId();

        if (!BulkUpdateTarget.TryCreate(request.Scope, request.TemplateKey, request.CategoryId,
                request.CollectionId, request.ExcludeItemId, out var target))
        {
            return BadRequest(InvalidTargetMessage);
        }

        var count = await _targets.CountAsync(target, workspaceId, HttpContext.RequestAborted);

        return Ok(new BulkUpdatePreviewResponse { AffectedItemCount = count });
    }

    [HttpPost]
    public ActionResult<BulkUpdateJobResponse> Enqueue(EnqueueBulkUpdateRequest request)
    {
        var workspaceId = GetWorkspaceId();
        var userId = TryGetUserId();
        if (userId is not > 0) return Unauthorized();

        if (!BulkUpdateTarget.TryCreate(request.Scope, request.TemplateKey, request.CategoryId,
                request.CollectionId, request.ExcludeItemId, out var target))
        {
            return BadRequest(InvalidTargetMessage);
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
            RequestedByUserId = userId.Value,
            Target = target,
            Diff = diff,
            NewPropertyOrder = newProps,
        };

        _queue.Enqueue(job);

        return StatusCode(StatusCodes.Status202Accepted, ToResponse(job));
    }

    [HttpGet("{jobId:guid}")]
    public ActionResult<BulkUpdateJobResponse> GetStatus(Guid jobId)
    {
        var workspaceId = GetWorkspaceId();
        var job = _jobs.GetJob(jobId, workspaceId);

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
        var job = _jobs.GetActiveJobForCollection(collectionId, workspaceId);

        if (job is null)
        {
            return NoContent();
        }

        return Ok(ToResponse(job));
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
