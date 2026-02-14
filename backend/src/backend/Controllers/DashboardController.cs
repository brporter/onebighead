using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DashboardController : ApiControllerBase
{
    private readonly IWorkspaceStatisticsRepository _statisticsRepository;

    public DashboardController(IWorkspaceStatisticsRepository statisticsRepository)
    {
        _statisticsRepository = statisticsRepository;
    }

    [HttpGet]
    public async Task<ActionResult<DashboardResponse>> GetDashboard()
    {
        var workspaceId = GetWorkspaceId();

        var aggregates = await _statisticsRepository.GetAggregatesAsync(workspaceId);

        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var weekAgo = today.AddDays(-6);

        var dailyViews = await _statisticsRepository.GetDailyAsync(
            workspaceId, StatisticType.DailyItemView, weekAgo, today);

        // Build exactly 7 entries, filling missing dates with zero
        var dailyViewLookup = dailyViews.ToDictionary(d => d.Date, d => d.Value);
        var dailyViewResponses = new List<DailyViewResponse>();
        for (var date = weekAgo; date <= today; date = date.AddDays(1))
        {
            dailyViewResponses.Add(new DailyViewResponse
            {
                Date = date.ToString("yyyy-MM-dd"),
                ViewCount = dailyViewLookup.GetValueOrDefault(date, 0),
            });
        }

        return Ok(new DashboardResponse
        {
            CollectionCount = aggregates.GetValueOrDefault(StatisticType.CollectionCount, 0),
            ItemCount = aggregates.GetValueOrDefault(StatisticType.ItemCount, 0),
            ImageCount = aggregates.GetValueOrDefault(StatisticType.ImageCount, 0),
            ImageTotalSizeBytes = aggregates.GetValueOrDefault(StatisticType.TotalImageSizeBytes, 0),
            DailyViews = dailyViewResponses,
        });
    }
}
