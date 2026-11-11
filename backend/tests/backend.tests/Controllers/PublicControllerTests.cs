using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using OneBigHead.Server.Controllers;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Services.PublicCatalog;

namespace OneBigHead.Server.Tests.Controllers;

public class PublicControllerTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Endpoints_DelegateRouteParametersAndRequestCancellationWithoutChangingResults(bool found)
    {
        using var cancellation = new CancellationTokenSource();
        var reader = new Mock<IPublicCatalogReader>(MockBehavior.Strict);
        var workspace = found ? new PublicWorkspaceDto { Name = "Gallery", Slug = "gallery" } : null;
        var collections = found ? new List<PublicCollectionDto>() : null;
        var collection = found ? new PublicCollectionDetailDto() : null;
        var items = found ? new List<PublicItemSummaryDto>() : null;
        var item = found ? new PublicItemDto { Id = 9 } : null;
        reader.Setup(r => r.GetWorkspaceAsync("gallery", cancellation.Token)).ReturnsAsync(workspace);
        reader.Setup(r => r.GetCollectionsAsync("gallery", cancellation.Token)).ReturnsAsync(collections);
        reader.Setup(r => r.GetCollectionAsync("gallery", 4, cancellation.Token)).ReturnsAsync(collection);
        reader.Setup(r => r.GetItemsAsync("gallery", 4, 8, cancellation.Token)).ReturnsAsync(items);
        reader.Setup(r => r.GetItemAsync("gallery", 9, cancellation.Token)).ReturnsAsync(item);
        var controller = new PublicController(reader.Object)
        {
            ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext { RequestAborted = cancellation.Token } }
        };
        Response(await controller.GetWorkspaceAsync("gallery"), workspace);
        Response(await controller.GetCollectionsAsync("gallery"), collections);
        Response(await controller.GetCollectionDetailAsync("gallery", 4), collection);
        Response(await controller.GetItemsAsync("gallery", 4, 8), items);
        Response(await controller.GetItemAsync("gallery", 9), item);
        reader.VerifyAll();
        Assert.Equal(5, reader.Invocations.Count);
    }

    private static void Response<T>(ActionResult<T> response, T? expected) where T : class
    {
        if (expected is null) Assert.IsType<NotFoundResult>(response.Result);
        else Assert.Same(expected, Assert.IsType<OkObjectResult>(response.Result).Value);
    }
}
