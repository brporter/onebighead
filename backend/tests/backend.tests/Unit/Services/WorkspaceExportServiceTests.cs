using System.Globalization;
using System.IO.Compression;
using System.Text.Json;
using Moq;
using OneBigHead.Server.Data;
using OneBigHead.Server.Services.Exports;

namespace OneBigHead.Server.Tests.Unit.Services;

public class WorkspaceExportServiceTests
{
    [Fact]
    public async Task Export_UsesOneUtcInstantForTheArchiveAndItsInvariantFileName()
    {
        var collections = new Mock<ICollectionRepository>();
        var categories = new Mock<ICategoryRepository>();
        var items = new Mock<IItemRepository>();
        var templates = new Mock<IItemTemplateRepository>();
        collections.Setup(repository => repository.GetAllAsync(7)).ReturnsAsync([]);
        categories.Setup(repository => repository.GetAllAsync(7)).ReturnsAsync([]);
        items.Setup(repository => repository.GetAllAsync(7)).ReturnsAsync([]);
        templates.Setup(repository => repository.GetWorkspaceTemplatesAsync(7)).ReturnsAsync([]);
        var clock = new Clock();
        var service = new WorkspaceExportService(collections.Object, categories.Object, items.Object, templates.Object, clock);
        var culture = CultureInfo.CurrentCulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA");
            var export = await service.ExportAsync(7);
            using var stream = export.Data;
            Assert.Equal(0, stream.Position);
            Assert.Equal("onebighead-export-2026-11-11-100001.zip", export.FileName);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            using var content = archive.GetEntry("export.json")!.Open();
            using var document = await JsonDocument.ParseAsync(content);
            Assert.Equal(new DateTime(2026, 11, 11, 10, 0, 1, DateTimeKind.Utc), document.RootElement.GetProperty("exportedAt").GetDateTime());
            Assert.Equal(1, clock.Calls);
        }
        finally { CultureInfo.CurrentCulture = culture; }
        collections.Verify(repository => repository.GetAllAsync(7), Times.Once);
        categories.Verify(repository => repository.GetAllAsync(7), Times.Once);
        items.Verify(repository => repository.GetAllAsync(7), Times.Once);
        templates.Verify(repository => repository.GetWorkspaceTemplatesAsync(7), Times.Once);
    }

    [Fact]
    public async Task ReadFailure_DoesNotProduceAPartialArchiveOrRetryTheRead()
    {
        var collections = new Mock<ICollectionRepository>();
        var categories = new Mock<ICategoryRepository>(MockBehavior.Strict);
        var items = new Mock<IItemRepository>(MockBehavior.Strict);
        var templates = new Mock<IItemTemplateRepository>(MockBehavior.Strict);
        var failure = new InvalidOperationException("Read unavailable");
        collections.Setup(repository => repository.GetAllAsync(7)).ThrowsAsync(failure);
        var service = new WorkspaceExportService(collections.Object, categories.Object, items.Object, templates.Object, new Clock());
        Assert.Same(failure, await Assert.ThrowsAsync<InvalidOperationException>(() => service.ExportAsync(7)));
        collections.Verify(repository => repository.GetAllAsync(7), Times.Once);
        categories.VerifyNoOtherCalls();
        items.VerifyNoOtherCalls();
        templates.VerifyNoOtherCalls();
    }

    private sealed class Clock : TimeProvider
    {
        public int Calls { get; private set; }
        public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 11, 11, 10, 0, 0, TimeSpan.Zero).AddSeconds(++Calls);
    }
}
