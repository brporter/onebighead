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
public class DashboardControllerTests
{
    private readonly Mock<IWorkspaceStatisticsRepository> _mockStatsRepository;
    private readonly DashboardController _controller;
    private const int TestWorkspaceId = 1;

    public DashboardControllerTests()
    {
        _mockStatsRepository = new Mock<IWorkspaceStatisticsRepository>();
        _controller = new DashboardController(_mockStatsRepository.Object);

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

    [Fact]
    public async Task GetDashboard_ReturnsOk_WithCorrectStats()
    {
        // Arrange
        var aggregates = new Dictionary<StatisticType, long>
        {
            { StatisticType.CollectionCount, 3 },
            { StatisticType.ItemCount, 42 },
            { StatisticType.ImageCount, 15 },
            { StatisticType.TotalImageSizeBytes, 1048576 },
        };
        _mockStatsRepository.Setup(r => r.GetAggregatesAsync(TestWorkspaceId))
            .ReturnsAsync(aggregates);
        _mockStatsRepository.Setup(r => r.GetDailyAsync(TestWorkspaceId, StatisticType.DailyItemView, It.IsAny<DateOnly>(), It.IsAny<DateOnly>()))
            .ReturnsAsync(new List<DailyStatistic>());

        // Act
        var result = await _controller.GetDashboard();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<DashboardResponse>(okResult.Value);
        Assert.Equal(3, response.CollectionCount);
        Assert.Equal(42, response.ItemCount);
        Assert.Equal(15, response.ImageCount);
        Assert.Equal(1048576, response.ImageTotalSizeBytes);
    }

    [Fact]
    public async Task GetDashboard_Returns7DaysOfViews_FillingGapsWithZero()
    {
        // Arrange
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var threeDaysAgo = today.AddDays(-3);
        var dailyStats = new List<DailyStatistic>
        {
            new(threeDaysAgo, 10),
            new(today, 5),
        };

        _mockStatsRepository.Setup(r => r.GetAggregatesAsync(TestWorkspaceId))
            .ReturnsAsync(new Dictionary<StatisticType, long>());
        _mockStatsRepository.Setup(r => r.GetDailyAsync(TestWorkspaceId, StatisticType.DailyItemView, It.IsAny<DateOnly>(), It.IsAny<DateOnly>()))
            .ReturnsAsync(dailyStats);

        // Act
        var result = await _controller.GetDashboard();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<DashboardResponse>(okResult.Value);
        Assert.Equal(7, response.DailyViews.Count);

        // Verify the two days with data have correct values
        var threeDaysAgoEntry = response.DailyViews.First(d => d.Date == threeDaysAgo.ToString("yyyy-MM-dd"));
        Assert.Equal(10, threeDaysAgoEntry.ViewCount);
        var todayEntry = response.DailyViews.First(d => d.Date == today.ToString("yyyy-MM-dd"));
        Assert.Equal(5, todayEntry.ViewCount);

        // Verify other days are zero
        var zeroDays = response.DailyViews.Where(d => d.Date != threeDaysAgo.ToString("yyyy-MM-dd") && d.Date != today.ToString("yyyy-MM-dd"));
        Assert.All(zeroDays, d => Assert.Equal(0, d.ViewCount));
    }

    [Fact]
    public async Task GetDashboard_ReturnsAllZeros_ForNewWorkspace()
    {
        // Arrange
        _mockStatsRepository.Setup(r => r.GetAggregatesAsync(TestWorkspaceId))
            .ReturnsAsync(new Dictionary<StatisticType, long>());
        _mockStatsRepository.Setup(r => r.GetDailyAsync(TestWorkspaceId, StatisticType.DailyItemView, It.IsAny<DateOnly>(), It.IsAny<DateOnly>()))
            .ReturnsAsync(new List<DailyStatistic>());

        // Act
        var result = await _controller.GetDashboard();

        // Assert
        var okResult = Assert.IsType<OkObjectResult>(result.Result);
        var response = Assert.IsType<DashboardResponse>(okResult.Value);
        Assert.Equal(0, response.CollectionCount);
        Assert.Equal(0, response.ItemCount);
        Assert.Equal(0, response.ImageCount);
        Assert.Equal(0, response.ImageTotalSizeBytes);
        Assert.Equal(7, response.DailyViews.Count);
        Assert.All(response.DailyViews, d => Assert.Equal(0, d.ViewCount));
    }
}
