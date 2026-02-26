using OneBigHead.Server.Data;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OneBigHead.Server.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class MatchesController : ApiControllerBase
{
    private readonly IMatchRepository _matchRepository;
    private readonly IMatchMessageRepository _messageRepository;
    private readonly IItemRepository _itemRepository;
    private readonly IWorkspaceRepository _workspaceRepository;

    public MatchesController(
        IMatchRepository matchRepository,
        IMatchMessageRepository messageRepository,
        IItemRepository itemRepository,
        IWorkspaceRepository workspaceRepository)
    {
        _matchRepository = matchRepository;
        _messageRepository = messageRepository;
        _itemRepository = itemRepository;
        _workspaceRepository = workspaceRepository;
    }

    [HttpGet]
    public async Task<ActionResult<MatchListResponse>> GetMatches(
        [FromQuery] MatchStatus? status = null,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 20)
    {
        var workspaceId = GetWorkspaceId();
        var matches = await _matchRepository.GetMatchesForWorkspaceAsync(workspaceId, status, skip, take);

        var response = new MatchListResponse
        {
            TotalCount = matches.Count,
            Matches = []
        };

        foreach (var match in matches)
        {
            var matchResponse = await BuildMatchResponseAsync(match, workspaceId);
            if (matchResponse != null)
            {
                response.Matches.Add(matchResponse);
            }
        }

        return Ok(response);
    }

    [HttpGet("{id}")]
    public async Task<ActionResult<MatchResponse>> GetMatch(int id)
    {
        var workspaceId = GetWorkspaceId();
        var match = await _matchRepository.GetByIdAsync(id);

        if (match == null)
            return NotFound();

        if (match.WantWorkspaceId != workspaceId && match.TradeWorkspaceId != workspaceId)
            return NotFound();

        var response = await BuildMatchResponseAsync(match, workspaceId);
        if (response == null)
            return NotFound();

        return Ok(response);
    }

    [HttpPut("{id}/status")]
    public async Task<IActionResult> UpdateStatus(int id, UpdateMatchStatusRequest request)
    {
        var workspaceId = GetWorkspaceId();
        var match = await _matchRepository.GetByIdAsync(id);

        if (match == null)
            return NotFound();

        if (match.WantWorkspaceId != workspaceId && match.TradeWorkspaceId != workspaceId)
            return NotFound();

        // Update the status on the requesting user's side only
        if (match.WantWorkspaceId == workspaceId)
        {
            match.WantUserStatus = request.Status;
        }
        else
        {
            match.TradeUserStatus = request.Status;
        }

        await _matchRepository.UpdateAsync(match);
        return NoContent();
    }

    [HttpGet("{id}/messages")]
    public async Task<ActionResult<List<MatchMessageResponse>>> GetMessages(
        int id,
        [FromQuery] int skip = 0,
        [FromQuery] int take = 50)
    {
        var workspaceId = GetWorkspaceId();
        var match = await _matchRepository.GetByIdAsync(id);

        if (match == null)
            return NotFound();

        if (match.WantWorkspaceId != workspaceId && match.TradeWorkspaceId != workspaceId)
            return NotFound();

        var messages = await _messageRepository.GetByMatchIdAsync(id, skip, take);

        var response = messages.Select(m => new MatchMessageResponse
        {
            Id = m.Id,
            Message = m.Message,
            IsMine = m.SenderWorkspaceId == workspaceId,
            IsRead = m.IsRead,
            CreatedAt = m.CreatedAt
        }).ToList();

        return Ok(response);
    }

    [HttpPost("{id}/messages")]
    public async Task<ActionResult<MatchMessageResponse>> SendMessage(
        int id, CreateMatchMessageRequest request)
    {
        var workspaceId = GetWorkspaceId();
        var userId = GetUserId();
        var match = await _matchRepository.GetByIdAsync(id);

        if (match == null)
            return NotFound();

        if (match.WantWorkspaceId != workspaceId && match.TradeWorkspaceId != workspaceId)
            return NotFound();

        var message = await _messageRepository.CreateAsync(new MatchMessage
        {
            ItemMatchId = id,
            SenderUserId = userId,
            SenderWorkspaceId = workspaceId,
            Message = request.Message
        });

        return Ok(new MatchMessageResponse
        {
            Id = message.Id,
            Message = message.Message,
            IsMine = true,
            IsRead = false,
            CreatedAt = message.CreatedAt
        });
    }

    [HttpPost("{id}/messages/read")]
    public async Task<IActionResult> MarkMessagesRead(int id)
    {
        var workspaceId = GetWorkspaceId();
        var match = await _matchRepository.GetByIdAsync(id);

        if (match == null)
            return NotFound();

        if (match.WantWorkspaceId != workspaceId && match.TradeWorkspaceId != workspaceId)
            return NotFound();

        await _messageRepository.MarkAsReadAsync(id, workspaceId);
        return NoContent();
    }

    [HttpGet("count")]
    public async Task<ActionResult<MatchCountResponse>> GetCount()
    {
        var workspaceId = GetWorkspaceId();

        var newMatchCount = await _matchRepository.GetNewMatchCountAsync(workspaceId);
        var unreadMessageCount = await _messageRepository.GetUnreadCountAsync(workspaceId);

        return Ok(new MatchCountResponse
        {
            NewMatchCount = newMatchCount,
            UnreadMessageCount = unreadMessageCount
        });
    }

    private async Task<MatchResponse?> BuildMatchResponseAsync(ItemMatch match, int workspaceId)
    {
        var wantItem = await _itemRepository.GetByIdCrossWorkspaceAsync(match.WantItemId);
        var tradeItem = await _itemRepository.GetByIdCrossWorkspaceAsync(match.TradeItemId);

        if (wantItem == null || tradeItem == null)
            return null;

        var wantWorkspace = await _workspaceRepository.GetByIdAsync(match.WantWorkspaceId);
        var tradeWorkspace = await _workspaceRepository.GetByIdAsync(match.TradeWorkspaceId);

        // Determine which side the requesting user is on
        var myStatus = match.WantWorkspaceId == workspaceId
            ? match.WantUserStatus
            : match.TradeUserStatus;

        // Check for unread messages
        var messages = await _messageRepository.GetByMatchIdAsync(match.Id, 0, 100);
        var hasUnread = messages.Any(m => !m.IsRead && m.SenderWorkspaceId != workspaceId);

        return new MatchResponse
        {
            Id = match.Id,
            WantItem = BuildItemSummary(wantItem, wantWorkspace),
            TradeItem = BuildItemSummary(tradeItem, tradeWorkspace),
            ConfidenceScore = match.ConfidenceScore,
            MatchReason = match.MatchReason,
            MyStatus = myStatus,
            CreatedAt = match.CreatedAt,
            HasUnreadMessages = hasUnread
        };
    }

    private static MatchItemSummary BuildItemSummary(Item item, Workspace? workspace)
    {
        return new MatchItemSummary
        {
            ItemId = item.Id ?? 0,
            Name = item.Name,
            Summary = item.Summary,
            PrimaryImageUrl = item.Images.Count > 0 ? item.Images[0].Url : null,
            WorkspaceName = workspace?.Name ?? "Unknown",
            WorkspaceId = item.WorkspaceId
        };
    }
}
