using OneBigHead.Server.Data;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Matching;
using Microsoft.Extensions.Logging;
using Moq;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class MatchingServiceTests
{
    private readonly Mock<IMatchRepository> _mockMatchRepository;
    private readonly Mock<IItemEmbeddingRepository> _mockEmbeddingRepository;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<IEmbeddingService> _mockEmbeddingService;
    private readonly MatchingService _service;

    public MatchingServiceTests()
    {
        _mockMatchRepository = new Mock<IMatchRepository>();
        _mockEmbeddingRepository = new Mock<IItemEmbeddingRepository>();
        _mockItemRepository = new Mock<IItemRepository>();
        _mockEmbeddingService = new Mock<IEmbeddingService>();
        var logger = new Mock<ILogger<MatchingService>>();

        _service = new MatchingService(
            _mockMatchRepository.Object,
            _mockEmbeddingRepository.Object,
            _mockItemRepository.Object,
            _mockEmbeddingService.Object,
            logger.Object);
    }

    [Fact]
    public async Task EnqueueForMatchingAsync_CreatesQueueEntry()
    {
        _mockMatchRepository.Setup(r => r.EnqueueAsync(It.IsAny<MatchQueueEntry>()))
            .ReturnsAsync((MatchQueueEntry e) => e);

        await _service.EnqueueForMatchingAsync(1, 1, MatchQueueReason.ItemCreated);

        _mockMatchRepository.Verify(r => r.EnqueueAsync(It.Is<MatchQueueEntry>(e =>
            e.ItemId == 1 &&
            e.WorkspaceId == 1 &&
            e.Reason == MatchQueueReason.ItemCreated &&
            e.Status == MatchQueueStatus.Pending)), Times.Once);
    }

    [Fact]
    public async Task EnqueueForMatchingAsync_DeduplicatesQueue()
    {
        _mockMatchRepository.Setup(r => r.EnqueueAsync(It.IsAny<MatchQueueEntry>()))
            .ReturnsAsync((MatchQueueEntry e) => e);

        await _service.EnqueueForMatchingAsync(42, 1, MatchQueueReason.ItemEdited);

        _mockMatchRepository.Verify(r => r.DeduplicateQueueAsync(42), Times.Once);
    }

    [Fact]
    public async Task FindCandidatesAsync_NoEmbedding_ReturnsEmpty()
    {
        var item = new Item { Id = 1, WorkspaceId = 1, Name = "Test" };
        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(1))
            .ReturnsAsync((ItemEmbedding?)null);

        var result = await _service.FindCandidatesAsync(item);

        Assert.Empty(result);
    }

    [Fact]
    public async Task FindCandidatesAsync_NoTradeEmbeddings_ReturnsEmpty()
    {
        var item = new Item { Id = 1, WorkspaceId = 1, Name = "Test" };
        var embedding = new ItemEmbedding
        {
            ItemId = 1,
            WorkspaceId = 1,
            Vector = new float[] { 1.0f, 0.0f }
        };

        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(1)).ReturnsAsync(embedding);
        _mockEmbeddingRepository.Setup(r => r.GetAllForTradeOrSellAsync(1)).ReturnsAsync(new List<ItemEmbedding>());

        var result = await _service.FindCandidatesAsync(item);

        Assert.Empty(result);
    }

    [Fact]
    public async Task FindCandidatesAsync_WithCandidates_ReturnsSortedBySimilarity()
    {
        var wantItem = new Item { Id = 1, WorkspaceId = 1, Name = "Test" };
        var wantEmbedding = new ItemEmbedding
        {
            ItemId = 1,
            WorkspaceId = 1,
            Vector = new float[] { 1.0f, 0.0f, 0.0f }
        };

        var tradeEmbeddings = new List<ItemEmbedding>
        {
            new() { ItemId = 10, WorkspaceId = 2, Vector = new float[] { 0.9f, 0.1f, 0.0f } },
            new() { ItemId = 11, WorkspaceId = 3, Vector = new float[] { 1.0f, 0.0f, 0.0f } },
            new() { ItemId = 12, WorkspaceId = 2, Vector = new float[] { 0.0f, 1.0f, 0.0f } }  // orthogonal, below threshold
        };

        _mockEmbeddingRepository.Setup(r => r.GetByItemIdAsync(1)).ReturnsAsync(wantEmbedding);
        _mockEmbeddingRepository.Setup(r => r.GetAllForTradeOrSellAsync(1)).ReturnsAsync(tradeEmbeddings);

        _mockEmbeddingService.Setup(s => s.CosineSimilarity(wantEmbedding.Vector, tradeEmbeddings[0].Vector))
            .Returns(0.99);
        _mockEmbeddingService.Setup(s => s.CosineSimilarity(wantEmbedding.Vector, tradeEmbeddings[1].Vector))
            .Returns(1.0);
        _mockEmbeddingService.Setup(s => s.CosineSimilarity(wantEmbedding.Vector, tradeEmbeddings[2].Vector))
            .Returns(0.0);

        var tradeItem10 = new Item { Id = 10, WorkspaceId = 2, Name = "Trade 10" };
        var tradeItem11 = new Item { Id = 11, WorkspaceId = 3, Name = "Trade 11" };

        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(10)).ReturnsAsync(tradeItem10);
        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(11)).ReturnsAsync(tradeItem11);

        var result = await _service.FindCandidatesAsync(wantItem);

        Assert.Equal(2, result.Count);
        // Should be sorted by similarity descending
        Assert.Equal(11, result[0].Item.Id);
        Assert.Equal(1.0, result[0].Similarity);
        Assert.Equal(10, result[1].Item.Id);
        Assert.Equal(0.99, result[1].Similarity);
    }

    [Fact]
    public async Task RemoveMatchesForItemAsync_DeletesMatchesAndEmbeddings()
    {
        await _service.RemoveMatchesForItemAsync(42);

        _mockMatchRepository.Verify(r => r.DeleteByItemIdAsync(42), Times.Once);
        _mockEmbeddingRepository.Verify(r => r.DeleteByItemIdAsync(42), Times.Once);
    }

    [Fact]
    public async Task InvalidateMatchesAsync_ResetsMatchStatuses()
    {
        var matches = new List<ItemMatch>
        {
            new() { Id = 1, WantItemId = 5, TradeItemId = 42, WantUserStatus = MatchStatus.Saved, TradeUserStatus = MatchStatus.Saved },
            new() { Id = 2, WantItemId = 42, TradeItemId = 7, WantUserStatus = MatchStatus.Saved, TradeUserStatus = MatchStatus.Saved }
        };

        _mockMatchRepository.Setup(r => r.GetMatchesForItemAsync(42)).ReturnsAsync(matches);

        await _service.InvalidateMatchesAsync(42, 2);

        // Only the match where 42 is TradeItemId should be reset
        _mockMatchRepository.Verify(r => r.UpdateAsync(It.Is<ItemMatch>(m =>
            m.Id == 1 &&
            m.WantUserStatus == MatchStatus.New &&
            m.TradeUserStatus == MatchStatus.New)), Times.Once);

        // Match where 42 is WantItemId should NOT be reset
        _mockMatchRepository.Verify(r => r.UpdateAsync(It.Is<ItemMatch>(m => m.Id == 2)), Times.Never);
    }
}
