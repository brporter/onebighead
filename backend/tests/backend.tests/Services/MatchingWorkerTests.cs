using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Matching;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class MatchingWorkerTests
{
    private readonly Mock<IMatchRepository> _mockMatchRepository;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<IEmbeddingService> _mockEmbeddingService;
    private readonly Mock<IItemEmbeddingRepository> _mockEmbeddingRepository;
    private readonly Mock<IMatchingService> _mockMatchingService;
    private readonly Mock<ILlmService> _mockLlmService;
    private readonly LlmSettings _settings;

    public MatchingWorkerTests()
    {
        _mockMatchRepository = new Mock<IMatchRepository>();
        _mockItemRepository = new Mock<IItemRepository>();
        _mockEmbeddingService = new Mock<IEmbeddingService>();
        _mockEmbeddingRepository = new Mock<IItemEmbeddingRepository>();
        _mockMatchingService = new Mock<IMatchingService>();
        _mockLlmService = new Mock<ILlmService>();

        _settings = new LlmSettings
        {
            Enabled = true,
            ConfidenceThreshold = 0.6,
            SimilarityThreshold = 0.5
        };
    }

    private MatchingWorker CreateWorker()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => _mockMatchRepository.Object);
        services.AddScoped(_ => _mockItemRepository.Object);
        services.AddScoped(_ => _mockEmbeddingService.Object);
        services.AddScoped(_ => _mockEmbeddingRepository.Object);
        services.AddScoped(_ => _mockMatchingService.Object);
        services.AddScoped(_ => _mockLlmService.Object);
        var sp = services.BuildServiceProvider();

        return new MatchingWorker(
            sp.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(_settings),
            new Mock<ILogger<MatchingWorker>>().Object);
    }

    [Fact]
    public async Task ExecuteAsync_DisabledSetting_ExitsImmediately()
    {
        _settings.Enabled = false;
        var worker = CreateWorker();
        var cts = new CancellationTokenSource();

        await worker.StartAsync(cts.Token);
        await Task.Delay(100); // Give it time to start
        await worker.StopAsync(cts.Token);

        _mockMatchRepository.Verify(r => r.DequeueAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task ExecuteAsync_EmptyQueue_DoesNotProcess()
    {
        var worker = CreateWorker();
        _mockMatchRepository.Setup(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry>());

        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200); // Wait for at least one poll
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockMatchRepository.Verify(r => r.DequeueAsync(It.IsAny<int>()), Times.AtLeastOnce);
        _mockItemRepository.Verify(r => r.GetByIdCrossWorkspaceAsync(It.IsAny<int>()), Times.Never);
    }

    [Fact]
    public async Task ProcessEntry_DeletedItem_RemovesMatches()
    {
        var entry = new MatchQueueEntry
        {
            Id = 1,
            ItemId = 42,
            WorkspaceId = 1,
            Status = MatchQueueStatus.Processing
        };

        _mockMatchRepository.SetupSequence(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry> { entry })
            .ReturnsAsync(new List<MatchQueueEntry>());

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(42))
            .ReturnsAsync((Item?)null);

        var worker = CreateWorker();
        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockMatchingService.Verify(s => s.RemoveMatchesForItemAsync(42), Times.Once);
        _mockMatchRepository.Verify(r => r.UpdateQueueEntryAsync(It.Is<MatchQueueEntry>(e =>
            e.Status == MatchQueueStatus.Completed)), Times.Once);
    }

    [Fact]
    public async Task ProcessEntry_HaveItem_RemovesMatches()
    {
        var entry = new MatchQueueEntry
        {
            Id = 1,
            ItemId = 42,
            WorkspaceId = 1,
            Status = MatchQueueStatus.Processing
        };

        var item = new Item
        {
            Id = 42,
            WorkspaceId = 1,
            Name = "Test",
            UserFlag = UserFlag.Have
        };

        _mockMatchRepository.SetupSequence(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry> { entry })
            .ReturnsAsync(new List<MatchQueueEntry>());

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(42)).ReturnsAsync(item);

        var worker = CreateWorker();
        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockMatchingService.Verify(s => s.RemoveMatchesForItemAsync(42), Times.Once);
    }

    [Fact]
    public async Task ProcessEntry_TradeOrSellItem_GeneratesEmbedding()
    {
        var entry = new MatchQueueEntry
        {
            Id = 1,
            ItemId = 42,
            WorkspaceId = 1,
            Status = MatchQueueStatus.Processing
        };

        var item = new Item
        {
            Id = 42,
            WorkspaceId = 1,
            Name = "Trade Item",
            UserFlag = UserFlag.TradeOrSell,
            Properties = new List<ItemProperty>()
        };

        _mockMatchRepository.SetupSequence(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry> { entry })
            .ReturnsAsync(new List<MatchQueueEntry>());

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(42)).ReturnsAsync(item);
        _mockEmbeddingService.Setup(s => s.ComputeContentHash(item)).Returns("hash123");
        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(42)).ReturnsAsync((ItemEmbedding?)null);
        _mockEmbeddingService.Setup(s => s.GenerateEmbeddingAsync(item, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new float[] { 1.0f, 0.0f });
        _mockEmbeddingRepository.Setup(r => r.UpsertAsync(It.IsAny<ItemEmbedding>()))
            .ReturnsAsync((ItemEmbedding e) => e);

        var worker = CreateWorker();
        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockEmbeddingService.Verify(s => s.GenerateEmbeddingAsync(item, It.IsAny<CancellationToken>()), Times.Once);
        _mockEmbeddingRepository.Verify(r => r.UpsertAsync(It.Is<ItemEmbedding>(e =>
            e.ItemId == 42 && e.ContentHash == "hash123")), Times.Once);
    }

    [Fact]
    public async Task ProcessEntry_WantItem_GeneratesEmbeddingAndEvaluates()
    {
        var entry = new MatchQueueEntry
        {
            Id = 1,
            ItemId = 42,
            WorkspaceId = 1,
            Status = MatchQueueStatus.Processing
        };

        var item = new Item
        {
            Id = 42,
            WorkspaceId = 1,
            Name = "Want Item",
            UserFlag = UserFlag.Want,
            Properties = new List<ItemProperty>()
        };

        var candidate = new Item { Id = 100, WorkspaceId = 2, Name = "Trade Item" };

        _mockMatchRepository.SetupSequence(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry> { entry })
            .ReturnsAsync(new List<MatchQueueEntry>());

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(42)).ReturnsAsync(item);
        _mockEmbeddingService.Setup(s => s.ComputeContentHash(item)).Returns("hash123");
        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(42)).ReturnsAsync((ItemEmbedding?)null);
        _mockEmbeddingService.Setup(s => s.GenerateEmbeddingAsync(item, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new float[] { 1.0f, 0.0f });
        _mockEmbeddingRepository.Setup(r => r.UpsertAsync(It.IsAny<ItemEmbedding>()))
            .ReturnsAsync((ItemEmbedding e) => e);

        _mockMatchingService.Setup(s => s.FindCandidatesAsync(item))
            .ReturnsAsync(new List<(Item, double)> { (candidate, 0.9) });

        _mockLlmService.Setup(s => s.EvaluateMatchesAsync(item, It.IsAny<List<Item>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<LlmMatchResult>
            {
                new() { ItemId = 100, ConfidenceScore = 0.85, Reason = "Good match" }
            });

        _mockMatchRepository.Setup(r => r.GetByItemPairAsync(42, 100)).ReturnsAsync((ItemMatch?)null);
        _mockMatchRepository.Setup(r => r.CreateAsync(It.IsAny<ItemMatch>()))
            .ReturnsAsync((ItemMatch m) => m);

        var worker = CreateWorker();
        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockMatchRepository.Verify(r => r.CreateAsync(It.Is<ItemMatch>(m =>
            m.WantItemId == 42 &&
            m.TradeItemId == 100 &&
            m.ConfidenceScore == 0.85 &&
            m.MatchReason == "Good match")), Times.Once);
    }

    [Fact]
    public async Task ProcessEntry_WantItem_BelowThreshold_DoesNotCreateMatch()
    {
        var entry = new MatchQueueEntry
        {
            Id = 1,
            ItemId = 42,
            WorkspaceId = 1,
            Status = MatchQueueStatus.Processing
        };

        var item = new Item
        {
            Id = 42,
            WorkspaceId = 1,
            Name = "Want Item",
            UserFlag = UserFlag.Want,
            Properties = new List<ItemProperty>()
        };

        _mockMatchRepository.SetupSequence(r => r.DequeueAsync(It.IsAny<int>()))
            .ReturnsAsync(new List<MatchQueueEntry> { entry })
            .ReturnsAsync(new List<MatchQueueEntry>());

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(42)).ReturnsAsync(item);
        _mockEmbeddingService.Setup(s => s.ComputeContentHash(item)).Returns("hash123");
        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(42)).ReturnsAsync((ItemEmbedding?)null);
        _mockEmbeddingService.Setup(s => s.GenerateEmbeddingAsync(item, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new float[] { 1.0f });
        _mockEmbeddingRepository.Setup(r => r.UpsertAsync(It.IsAny<ItemEmbedding>()))
            .ReturnsAsync((ItemEmbedding e) => e);

        _mockMatchingService.Setup(s => s.FindCandidatesAsync(item))
            .ReturnsAsync(new List<(Item, double)> { (new Item { Id = 100, WorkspaceId = 2, Name = "Trade" }, 0.8) });

        _mockLlmService.Setup(s => s.EvaluateMatchesAsync(item, It.IsAny<List<Item>>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<LlmMatchResult>
            {
                new() { ItemId = 100, ConfidenceScore = 0.3, Reason = "Poor match" }
            });

        var worker = CreateWorker();
        var cts = new CancellationTokenSource();
        await worker.StartAsync(cts.Token);
        await Task.Delay(200);
        cts.Cancel();
        await worker.StopAsync(CancellationToken.None);

        _mockMatchRepository.Verify(r => r.CreateAsync(It.IsAny<ItemMatch>()), Times.Never);
    }
}
