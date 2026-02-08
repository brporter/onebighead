using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.BulkUpdate;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class BulkUpdatesControllerTests
{
    private readonly Mock<IBulkUpdateQueue> _mockQueue;
    private readonly Mock<IPropertyDiffService> _mockDiffService;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly BulkUpdatesController _controller;
    private const int TestWorkspaceId = 1;

    public BulkUpdatesControllerTests()
    {
        _mockQueue = new Mock<IBulkUpdateQueue>();
        _mockDiffService = new Mock<IPropertyDiffService>();
        _mockItemRepository = new Mock<IItemRepository>();
        _controller = new BulkUpdatesController(
            _mockQueue.Object,
            _mockDiffService.Object,
            _mockItemRepository.Object);

        var claims = new List<Claim>
        {
            new("workspace_id", TestWorkspaceId.ToString()),
            new(ClaimTypes.NameIdentifier, "1"),
            new(ClaimTypes.Email, "test@example.com")
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var claimsPrincipal = new ClaimsPrincipal(identity);

        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext { User = claimsPrincipal }
        };
    }

    #region Preview Tests

    [Fact]
    public async Task Preview_Template_ReturnsCorrectCount()
    {
        var templateKey = Guid.NewGuid();
        _mockItemRepository.Setup(r => r.CountByTemplateKeyAsync(templateKey, TestWorkspaceId))
            .ReturnsAsync(5);

        var request = new BulkUpdatePreviewRequest
        {
            Scope = "template",
            TemplateKey = templateKey,
        };

        var result = await _controller.Preview(request);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<BulkUpdatePreviewResponse>(okResult.Value);
        Assert.Equal(5, response.AffectedItemCount);
    }

    [Fact]
    public async Task Preview_Category_ReturnsCorrectCount()
    {
        _mockItemRepository.Setup(r => r.CountByCategoryIdAsync(10, TestWorkspaceId))
            .ReturnsAsync(3);

        var request = new BulkUpdatePreviewRequest
        {
            Scope = "category",
            CategoryId = 10,
        };

        var result = await _controller.Preview(request);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<BulkUpdatePreviewResponse>(okResult.Value);
        Assert.Equal(3, response.AffectedItemCount);
    }

    [Fact]
    public async Task Preview_Collection_ReturnsCorrectCount()
    {
        _mockItemRepository.Setup(r => r.CountByCollectionIdAsync(5, TestWorkspaceId))
            .ReturnsAsync(10);

        var request = new BulkUpdatePreviewRequest
        {
            Scope = "collection",
            CollectionId = 5,
        };

        var result = await _controller.Preview(request);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<BulkUpdatePreviewResponse>(okResult.Value);
        Assert.Equal(10, response.AffectedItemCount);
    }

    [Fact]
    public async Task Preview_WithExcludeItemId_SubtractsOne()
    {
        var templateKey = Guid.NewGuid();
        _mockItemRepository.Setup(r => r.CountByTemplateKeyAsync(templateKey, TestWorkspaceId))
            .ReturnsAsync(5);

        var request = new BulkUpdatePreviewRequest
        {
            Scope = "template",
            TemplateKey = templateKey,
            ExcludeItemId = 42,
        };

        var result = await _controller.Preview(request);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<BulkUpdatePreviewResponse>(okResult.Value);
        Assert.Equal(4, response.AffectedItemCount);
    }

    [Fact]
    public async Task Preview_InvalidScope_ReturnsBadRequest()
    {
        var request = new BulkUpdatePreviewRequest { Scope = "invalid" };

        var result = await _controller.Preview(request);

        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion

    #region Enqueue Tests

    [Fact]
    public void Enqueue_ReturnsAcceptedWithJobId()
    {
        _mockDiffService.Setup(d => d.ComputeDiff(
                It.IsAny<List<PropertyIdentifier>>(),
                It.IsAny<List<PropertyIdentifier>>(),
                It.IsAny<List<PropertyRenameMapping>>()))
            .Returns(new PropertyDiff(new List<PropertyChange>()));

        var request = new EnqueueBulkUpdateRequest
        {
            Scope = "template",
            TemplateKey = Guid.NewGuid(),
            OldProperties = new List<PropertyIdentifierDto> { new() { Category = "Specs", Name = "CPU" } },
            NewProperties = new List<PropertyIdentifierDto> { new() { Category = "Specs", Name = "RAM" } },
        };

        var result = _controller.Enqueue(request);

        var objectResult = Assert.IsType<ObjectResult>(result.Result);
        Assert.Equal(StatusCodes.Status202Accepted, objectResult.StatusCode);
        var response = Assert.IsType<BulkUpdateJobResponse>(objectResult.Value);
        Assert.NotEqual(Guid.Empty, response.JobId);
        Assert.Equal("Queued", response.Status);

        _mockQueue.Verify(q => q.Enqueue(It.IsAny<BulkUpdateJob>()), Times.Once);
    }

    [Fact]
    public void Enqueue_InvalidScope_ReturnsBadRequest()
    {
        var request = new EnqueueBulkUpdateRequest
        {
            Scope = "invalid",
            OldProperties = new List<PropertyIdentifierDto>(),
            NewProperties = new List<PropertyIdentifierDto>(),
        };

        var result = _controller.Enqueue(request);

        Assert.IsType<BadRequestObjectResult>(result.Result);
    }

    #endregion

    #region GetStatus Tests

    [Fact]
    public void GetStatus_ExistingJob_ReturnsJob()
    {
        var jobId = Guid.NewGuid();
        var job = new BulkUpdateJob
        {
            JobId = jobId,
            WorkspaceId = TestWorkspaceId,
            Status = BulkUpdateJobStatus.Running,
            TotalItems = 10,
            ProcessedItems = 5,
            Diff = new PropertyDiff(new List<PropertyChange>()),
        };

        _mockQueue.Setup(q => q.GetJob(jobId, TestWorkspaceId)).Returns(job);

        var result = _controller.GetStatus(jobId);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<BulkUpdateJobResponse>(okResult.Value);
        Assert.Equal(jobId, response.JobId);
        Assert.Equal("Running", response.Status);
        Assert.Equal(10, response.TotalItems);
        Assert.Equal(5, response.ProcessedItems);
    }

    [Fact]
    public void GetStatus_NonExistentJob_ReturnsNotFound()
    {
        _mockQueue.Setup(q => q.GetJob(It.IsAny<Guid>(), TestWorkspaceId))
            .Returns((BulkUpdateJob?)null);

        var result = _controller.GetStatus(Guid.NewGuid());

        Assert.IsType<NotFoundResult>(result.Result);
    }

    #endregion

    #region GetCollectionStatus Tests

    [Fact]
    public void GetCollectionStatus_ActiveJob_ReturnsJob()
    {
        var job = new BulkUpdateJob
        {
            WorkspaceId = TestWorkspaceId,
            Status = BulkUpdateJobStatus.Running,
            CollectionId = 10,
            Diff = new PropertyDiff(new List<PropertyChange>()),
        };

        _mockQueue.Setup(q => q.GetActiveJobForCollection(10, TestWorkspaceId)).Returns(job);

        var result = _controller.GetCollectionStatus(10);

        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        Assert.IsType<BulkUpdateJobResponse>(okResult.Value);
    }

    [Fact]
    public void GetCollectionStatus_NoActiveJob_ReturnsNoContent()
    {
        _mockQueue.Setup(q => q.GetActiveJobForCollection(10, TestWorkspaceId))
            .Returns((BulkUpdateJob?)null);

        var result = _controller.GetCollectionStatus(10);

        Assert.IsType<NoContentResult>(result.Result);
    }

    #endregion
}
