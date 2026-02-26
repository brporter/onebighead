using OneBigHead.Server.Controllers;
using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System.Security.Claims;

namespace OneBigHead.Server.Tests.Controllers;

[Trait("Category", "Unit")]
public class MatchesControllerTests
{
    private readonly Mock<IMatchRepository> _mockMatchRepository;
    private readonly Mock<IMatchMessageRepository> _mockMessageRepository;
    private readonly Mock<IItemRepository> _mockItemRepository;
    private readonly Mock<IWorkspaceRepository> _mockWorkspaceRepository;
    private readonly MatchesController _controller;
    private const int TestWorkspaceId = 1;
    private const int OtherWorkspaceId = 2;

    public MatchesControllerTests()
    {
        _mockMatchRepository = new Mock<IMatchRepository>();
        _mockMessageRepository = new Mock<IMatchMessageRepository>();
        _mockItemRepository = new Mock<IItemRepository>();
        _mockWorkspaceRepository = new Mock<IWorkspaceRepository>();

        _controller = new MatchesController(
            _mockMatchRepository.Object,
            _mockMessageRepository.Object,
            _mockItemRepository.Object,
            _mockWorkspaceRepository.Object);

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

    private void SetupItemAndWorkspace(int itemId, int workspaceId, string name)
    {
        _mockItemRepository.Setup(r => r.GetByIdCrossWorkspaceAsync(itemId))
            .ReturnsAsync(new Item
            {
                Id = itemId,
                WorkspaceId = workspaceId,
                Name = name,
                Properties = new List<ItemProperty>(),
                Images = new List<ItemImage>()
            });
        _mockWorkspaceRepository.Setup(r => r.GetByIdAsync(workspaceId))
            .ReturnsAsync(new Workspace { Id = workspaceId, Name = $"Workspace {workspaceId}" });
    }

    [Fact]
    public async Task GetMatches_ReturnsMatchesForWorkspace()
    {
        var matches = new List<ItemMatch>
        {
            new()
            {
                Id = 1,
                WantItemId = 10,
                WantWorkspaceId = TestWorkspaceId,
                TradeItemId = 20,
                TradeWorkspaceId = OtherWorkspaceId,
                ConfidenceScore = 0.85,
                MatchReason = "Good match",
                CreatedAt = DateTime.UtcNow
            }
        };

        _mockMatchRepository.Setup(r => r.GetMatchesForWorkspaceAsync(TestWorkspaceId, null, 0, 20))
            .ReturnsAsync(matches);

        SetupItemAndWorkspace(10, TestWorkspaceId, "Want Item");
        SetupItemAndWorkspace(20, OtherWorkspaceId, "Trade Item");
        _mockMessageRepository.Setup(r => r.GetByMatchIdAsync(1, 0, 100))
            .ReturnsAsync(new List<MatchMessage>());

        var result = await _controller.GetMatches();
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<MatchListResponse>(okResult.Value);

        Assert.Single(response.Matches);
        Assert.Equal(0.85, response.Matches[0].ConfidenceScore);
        Assert.Equal("Want Item", response.Matches[0].WantItem.Name);
        Assert.Equal("Trade Item", response.Matches[0].TradeItem.Name);
    }

    [Fact]
    public async Task GetMatch_NotFound_Returns404()
    {
        _mockMatchRepository.Setup(r => r.GetByIdAsync(999)).ReturnsAsync((ItemMatch?)null);

        var result = await _controller.GetMatch(999);

        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetMatch_WrongWorkspace_Returns404()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = 99,
            TradeWorkspaceId = 98
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var result = await _controller.GetMatch(1);

        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task UpdateStatus_WantSide_UpdatesWantUserStatus()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = TestWorkspaceId,
            TradeWorkspaceId = OtherWorkspaceId,
            WantUserStatus = MatchStatus.New,
            TradeUserStatus = MatchStatus.New
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var result = await _controller.UpdateStatus(1, new UpdateMatchStatusRequest { Status = MatchStatus.Saved });

        Assert.IsType<NoContentResult>(result);
        _mockMatchRepository.Verify(r => r.UpdateAsync(It.Is<ItemMatch>(m =>
            m.WantUserStatus == MatchStatus.Saved &&
            m.TradeUserStatus == MatchStatus.New)), Times.Once);
    }

    [Fact]
    public async Task UpdateStatus_TradeSide_UpdatesTradeUserStatus()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = OtherWorkspaceId,
            TradeWorkspaceId = TestWorkspaceId,
            WantUserStatus = MatchStatus.New,
            TradeUserStatus = MatchStatus.New
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var result = await _controller.UpdateStatus(1, new UpdateMatchStatusRequest { Status = MatchStatus.Dismissed });

        Assert.IsType<NoContentResult>(result);
        _mockMatchRepository.Verify(r => r.UpdateAsync(It.Is<ItemMatch>(m =>
            m.WantUserStatus == MatchStatus.New &&
            m.TradeUserStatus == MatchStatus.Dismissed)), Times.Once);
    }

    [Fact]
    public async Task SendMessage_ValidMatch_ReturnsMessage()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = TestWorkspaceId,
            TradeWorkspaceId = OtherWorkspaceId
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);
        _mockMessageRepository.Setup(r => r.CreateAsync(It.IsAny<MatchMessage>()))
            .ReturnsAsync((MatchMessage m) =>
            {
                m.Id = 1;
                m.CreatedAt = DateTime.UtcNow;
                return m;
            });

        var result = await _controller.SendMessage(1, new CreateMatchMessageRequest { Message = "Hello!" });
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<MatchMessageResponse>(okResult.Value);

        Assert.Equal("Hello!", response.Message);
        Assert.True(response.IsMine);
    }

    [Fact]
    public async Task SendMessage_WrongWorkspace_Returns404()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = 99,
            TradeWorkspaceId = 98
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var result = await _controller.SendMessage(1, new CreateMatchMessageRequest { Message = "Hello!" });

        Assert.IsType<NotFoundResult>(result.Result);
    }

    [Fact]
    public async Task GetMessages_ReturnsMessagesWithCorrectIsMineFlag()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = TestWorkspaceId,
            TradeWorkspaceId = OtherWorkspaceId
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var messages = new List<MatchMessage>
        {
            new() { Id = 1, SenderWorkspaceId = TestWorkspaceId, Message = "My message", CreatedAt = DateTime.UtcNow },
            new() { Id = 2, SenderWorkspaceId = OtherWorkspaceId, Message = "Their message", CreatedAt = DateTime.UtcNow }
        };
        _mockMessageRepository.Setup(r => r.GetByMatchIdAsync(1, 0, 50)).ReturnsAsync(messages);

        var result = await _controller.GetMessages(1);
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<List<MatchMessageResponse>>(okResult.Value);

        Assert.Equal(2, response.Count);
        Assert.True(response[0].IsMine);
        Assert.False(response[1].IsMine);
    }

    [Fact]
    public async Task MarkMessagesRead_ValidMatch_ReturnsNoContent()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantWorkspaceId = TestWorkspaceId,
            TradeWorkspaceId = OtherWorkspaceId
        };
        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);

        var result = await _controller.MarkMessagesRead(1);

        Assert.IsType<NoContentResult>(result);
        _mockMessageRepository.Verify(r => r.MarkAsReadAsync(1, TestWorkspaceId), Times.Once);
    }

    [Fact]
    public async Task GetCount_ReturnsCounts()
    {
        _mockMatchRepository.Setup(r => r.GetNewMatchCountAsync(TestWorkspaceId)).ReturnsAsync(5);
        _mockMessageRepository.Setup(r => r.GetUnreadCountAsync(TestWorkspaceId)).ReturnsAsync(3);

        var result = await _controller.GetCount();
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<MatchCountResponse>(okResult.Value);

        Assert.Equal(5, response.NewMatchCount);
        Assert.Equal(3, response.UnreadMessageCount);
    }

    [Fact]
    public async Task GetMatches_WithStatusFilter_PassesFilterToRepository()
    {
        _mockMatchRepository.Setup(r => r.GetMatchesForWorkspaceAsync(TestWorkspaceId, MatchStatus.Saved, 0, 20))
            .ReturnsAsync(new List<ItemMatch>());

        await _controller.GetMatches(status: MatchStatus.Saved);

        _mockMatchRepository.Verify(r => r.GetMatchesForWorkspaceAsync(TestWorkspaceId, MatchStatus.Saved, 0, 20), Times.Once);
    }

    [Fact]
    public async Task GetMatch_WantSide_ReturnsCorrectMyStatus()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantItemId = 10,
            WantWorkspaceId = TestWorkspaceId,
            TradeItemId = 20,
            TradeWorkspaceId = OtherWorkspaceId,
            WantUserStatus = MatchStatus.Saved,
            TradeUserStatus = MatchStatus.Dismissed,
            ConfidenceScore = 0.9,
            MatchReason = "Great match",
            CreatedAt = DateTime.UtcNow
        };

        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);
        SetupItemAndWorkspace(10, TestWorkspaceId, "Want Item");
        SetupItemAndWorkspace(20, OtherWorkspaceId, "Trade Item");
        _mockMessageRepository.Setup(r => r.GetByMatchIdAsync(1, 0, 100))
            .ReturnsAsync(new List<MatchMessage>());

        var result = await _controller.GetMatch(1);
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<MatchResponse>(okResult.Value);

        Assert.Equal(MatchStatus.Saved, response.MyStatus);
    }

    [Fact]
    public async Task GetMatch_HasUnreadMessages_SetsFlag()
    {
        var match = new ItemMatch
        {
            Id = 1,
            WantItemId = 10,
            WantWorkspaceId = TestWorkspaceId,
            TradeItemId = 20,
            TradeWorkspaceId = OtherWorkspaceId,
            ConfidenceScore = 0.85,
            CreatedAt = DateTime.UtcNow
        };

        _mockMatchRepository.Setup(r => r.GetByIdAsync(1)).ReturnsAsync(match);
        SetupItemAndWorkspace(10, TestWorkspaceId, "Want Item");
        SetupItemAndWorkspace(20, OtherWorkspaceId, "Trade Item");

        var messages = new List<MatchMessage>
        {
            new() { Id = 1, SenderWorkspaceId = OtherWorkspaceId, IsRead = false, Message = "Hi" }
        };
        _mockMessageRepository.Setup(r => r.GetByMatchIdAsync(1, 0, 100)).ReturnsAsync(messages);

        var result = await _controller.GetMatch(1);
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<MatchResponse>(okResult.Value);

        Assert.True(response.HasUnreadMessages);
    }
}
