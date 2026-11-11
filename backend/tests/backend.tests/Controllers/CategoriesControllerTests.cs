using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.Categories;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class CategoriesControllerTests
{
    private readonly Mock<ICategoryReadService> _reads = new(MockBehavior.Strict);
    private readonly Mock<ICategoryWriteService> _writes = new(MockBehavior.Strict);
    private readonly CategoriesController _controller;

    public CategoriesControllerTests()
    {
        _controller = new CategoriesController(_reads.Object, _writes.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext
            { User = new ClaimsPrincipal(new ClaimsIdentity([new Claim("workspace_id", "7")], "TestAuth")) } }
        };
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData(1, false)]
    [InlineData(99, true)]
    public async Task List_ForwardsScopeAndMapsMissingCollection(int? collectionId, bool missing)
    {
        IReadOnlyList<CategoryResponse>? response = missing ? null : [new() { CategoryId = 5 }];
        _reads.Setup(reads => reads.GetAllAsync(7, collectionId)).ReturnsAsync(response);
        var result = await _controller.GetCategories(collectionId);
        if (missing) Assert.Equal("Collection not found", Assert.IsType<NotFoundObjectResult>(result.Result).Value);
        else Assert.Same(response, Assert.IsType<OkObjectResult>(result.Result).Value);
        _reads.VerifyAll();
        _writes.VerifyNoOtherCalls();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Detail_ForwardsScopeAndMapsMissingCategory(bool missing)
    {
        var response = missing ? null : new CategoryResponse { CategoryId = 5 };
        _reads.Setup(reads => reads.GetByIdAsync(5, 7)).ReturnsAsync(response);
        var result = await _controller.GetCategory(5);
        if (missing) Assert.IsType<NotFoundResult>(result.Result);
        else Assert.Same(response, Assert.IsType<OkObjectResult>(result.Result).Value);
        _reads.VerifyAll();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Templates_ForwardsScopeAndMapsMissingCategory(bool missing)
    {
        IReadOnlyList<int>? response = missing ? null : [3, 1];
        _reads.Setup(reads => reads.GetInheritedTemplateIdsAsync(5, 7)).ReturnsAsync(response);
        var result = await _controller.GetCategoryTemplates(5);
        if (missing) Assert.IsType<NotFoundResult>(result.Result);
        else Assert.Same(response, Assert.IsType<OkObjectResult>(result.Result).Value);
        _reads.VerifyAll();
    }

    [Fact]
    public async Task Create_ForwardsRequestAndCancellation_AndReturnsCommittedIdentity()
    {
        using var cancellation = new CancellationTokenSource();
        var request = new CreateCategoryRequest { Name = "New", CollectionId = 9 };
        var response = new CategoryResponse { CategoryId = 42, Name = "New", ItemTemplateIds = [2, 1] };
        _writes.Setup(writes => writes.CreateAsync(7, request, cancellation.Token)).ReturnsAsync(CategoryWriteResult<CategoryResponse>.Success(response));
        var result = Assert.IsType<CreatedAtActionResult>((await _controller.CreateCategory(request, cancellation.Token)).Result);
        Assert.Same(response, result.Value);
        Assert.Equal(nameof(CategoriesController.GetCategory), result.ActionName);
        Assert.Equal(42, result.RouteValues!["id"]);
        _writes.VerifyAll();
    }

    [Fact]
    public async Task Update_ReturnsCommittedProjection()
    {
        var request = new UpdateCategoryRequest { Name = "Edited" };
        var response = new CategoryResponse { CategoryId = 42, Name = "Edited" };
        _writes.Setup(writes => writes.UpdateAsync(42, 7, request, default)).ReturnsAsync(CategoryWriteResult<CategoryResponse>.Success(response));
        var result = await _controller.UpdateCategory(42, request);
        Assert.Same(response, Assert.IsType<OkObjectResult>(result.Result).Value);
        _writes.VerifyAll();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reorder_ReadsOnlyAfterCommit_AndHandlesCollectionRemovedBeforeRefresh(bool missing)
    {
        var request = new ReorderCategoriesRequest();
        IReadOnlyList<CategoryResponse>? response = missing ? null : [new() { CategoryId = 42, SortOrder = 0, EffectiveIsPublic = true, ItemTemplateIds = [2, 1] }];
        var sequence = new MockSequence();
        _writes.InSequence(sequence).Setup(writes => writes.ReorderAsync(7, request, default)).ReturnsAsync(CategoryWriteResult<int>.Success(9));
        _reads.InSequence(sequence).Setup(reads => reads.GetAllAsync(7, 9)).ReturnsAsync(response);
        var result = await _controller.ReorderCategories(request);
        if (missing) Assert.IsType<NotFoundObjectResult>(result.Result);
        else Assert.Same(response, Assert.IsType<OkObjectResult>(result.Result).Value);
        _writes.VerifyAll();
        _reads.VerifyAll();
    }

    [Fact]
    public async Task Delete_ReturnsNoContentAfterCommit()
    {
        _writes.Setup(writes => writes.DeleteAsync(42, 7, default)).ReturnsAsync(CategoryWriteResult<bool>.Success(true));
        Assert.IsType<NoContentResult>(await _controller.DeleteCategory(42));
        _writes.VerifyAll();
    }

    [Theory]
    [InlineData(CategoryWriteFailure.Invalid, 400)]
    [InlineData(CategoryWriteFailure.NotFound, 404)]
    [InlineData(CategoryWriteFailure.Forbidden, 403)]
    [InlineData(CategoryWriteFailure.Conflict, 409)]
    public async Task Mutations_MapRejectionsConsistently_WithoutRefreshing(CategoryWriteFailure kind, int status)
    {
        var error = new CategoryWriteError(kind, "Reason");
        var create = new CreateCategoryRequest();
        var update = new UpdateCategoryRequest();
        var reorder = new ReorderCategoriesRequest();
        _writes.Setup(writes => writes.CreateAsync(7, create, default)).ReturnsAsync(CategoryWriteResult<CategoryResponse>.Failure(error));
        _writes.Setup(writes => writes.UpdateAsync(42, 7, update, default)).ReturnsAsync(CategoryWriteResult<CategoryResponse>.Failure(error));
        _writes.Setup(writes => writes.ReorderAsync(7, reorder, default)).ReturnsAsync(CategoryWriteResult<int>.Failure(error));
        _writes.Setup(writes => writes.DeleteAsync(42, 7, default)).ReturnsAsync(CategoryWriteResult<bool>.Failure(error));
        IActionResult?[] results = [(await _controller.CreateCategory(create)).Result,
            (await _controller.UpdateCategory(42, update)).Result,
            (await _controller.ReorderCategories(reorder)).Result, await _controller.DeleteCategory(42)];
        foreach (var result in results)
        {
            var response = Assert.IsAssignableFrom<ObjectResult>(result);
            Assert.Equal(status, response.StatusCode);
            Assert.Equal("Reason", response.Value);
        }
        _reads.VerifyNoOtherCalls();
        _writes.VerifyAll();
    }

    [Fact]
    public async Task UnknownFailure_IsNotSilentlyReturnedAsSuccess()
    {
        _writes.Setup(writes => writes.DeleteAsync(42, 7, default))
            .ReturnsAsync(CategoryWriteResult<bool>.Failure(new((CategoryWriteFailure)99, "Invalid adapter result")));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _controller.DeleteCategory(42));
    }
}
