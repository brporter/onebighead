using Microsoft.EntityFrameworkCore;
using OneBigHead.Server.Data;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration.Postgres;

[Collection(PostgresIntegrationCollection.Name)]
[Trait("Category", "PostgresIntegration")]
public class SupportRepositoryPostgresTests(PostgresIntegrationFixture fixture) : IAsyncLifetime
{
    private static readonly DateTime Timestamp = new(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private SupportRepository Repository => new(fixture.CreateContextFactory());

    public async Task InitializeAsync()
    {
        await fixture.ResetAsync();
        await using var db = fixture.CreateContext();
        db.Users.AddRange(new User { Id = 1, Email = "first@example.test" }, new User { Id = 2, Email = "second@example.test" });
        db.SupportRequests.AddRange(Enumerable.Range(1, 6).Select(id => new SupportRequest
        {
            Id = id, UserId = id == 6 ? 2 : 1, Email = "request@example.test", Subject = $"Ticket {id}",
            Description = "Description", Status = id % 2 == 0 ? SupportRequestStatus.Closed : SupportRequestStatus.Open,
            CreatedAt = Timestamp, UpdatedAt = id == 1 ? Timestamp.AddDays(1) : Timestamp,
            IsDeleted = id == 4, DeletedAt = id == 4 ? Timestamp : null
        }));
        db.SupportReplies.AddRange(
            new SupportReply { Id = 1, SupportRequestId = 1, UserId = 2, IsFromAdmin = true, Message = "Unread", IsRead = false },
            new SupportReply { Id = 2, SupportRequestId = 1, UserId = 1, IsFromAdmin = false, Message = "Owner", IsRead = false },
            new SupportReply { Id = 3, SupportRequestId = 1, UserId = 2, IsFromAdmin = true, Message = "Read", IsRead = true },
            new SupportReply { Id = 4, SupportRequestId = 4, UserId = 2, IsFromAdmin = true, Message = "Deleted ticket", IsRead = false },
            new SupportReply { Id = 5, SupportRequestId = 6, UserId = 1, IsFromAdmin = true, Message = "Other owner", IsRead = false });
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    [Theory]
    [InlineData(null, false, 5)]
    [InlineData(null, true, 6)]
    [InlineData(SupportRequestStatus.Closed, false, 2)]
    [InlineData(SupportRequestStatus.Closed, true, 3)]
    [InlineData(SupportRequestStatus.Resolved, true, 0)]
    public async Task FilteredCount_MatchesVisibleRequestsAndPages(SupportRequestStatus? status, bool deleted, int expected)
    {
        var repository = Repository;
        var all = (await repository.GetAllRequestsAsync(status, deleted)).ToArray();
        Assert.Equal(expected, all.Length);
        Assert.Equal(expected, await repository.GetRequestCountAsync(status, deleted));
        var ids = all.Select(r => r.Id).ToArray();
        var paged = new List<int>();
        for (var offset = 0; offset < expected; offset += 2)
            paged.AddRange((await repository.GetAllRequestsAsync(status, deleted, 2, offset)).Select(r => r.Id));
        Assert.Equal(ids, paged);
        Assert.Empty(await repository.GetAllRequestsAsync(status, deleted, 2, expected));
    }

    [Fact]
    public async Task EqualTimestamps_HaveStableOrderAcrossPagesAndOwnerLists()
    {
        Assert.Equal(new[] { 1, 6, 5, 3, 2 }, (await Repository.GetAllRequestsAsync()).Select(r => r.Id));
        Assert.Equal(new[] { 1, 5, 3, 2 }, (await Repository.GetRequestsForUserAsync(1)).Select(r => r.Id));
        Assert.Equal(new[] { 1, 5, 4, 3, 2 }, (await Repository.GetRequestsForUserAsync(1, true)).Select(r => r.Id));
        Assert.Equal(new[] { 5, 3 }, (await Repository.GetAllRequestsAsync(limit: 2, offset: 2)).Select(r => r.Id));
        Assert.Empty(await Repository.GetRequestsForUserAsync(999));
    }

    [Fact]
    public async Task StatusChange_ReturnsRepliesAndPreservesOriginalRequest()
    {
        var start = DateTime.UtcNow;
        var changed = await Repository.UpdateStatusAsync(1, SupportRequestStatus.InProgress);
        Assert.NotNull(changed);
        Assert.Equal(SupportRequestStatus.InProgress, changed.Status);
        Assert.Equal(3, changed.Replies.Count);
        await using var check = fixture.CreateContext();
        var saved = await check.SupportRequests.SingleAsync(r => r.Id == 1);
        Assert.Equal(changed.Status, saved.Status);
        Assert.InRange(saved.UpdatedAt, start, DateTime.UtcNow);
        Assert.Equal(Timestamp, saved.CreatedAt);
        Assert.Equal("Description", saved.Description);
        Assert.Equal(1, saved.UserId);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(999)]
    public async Task MissingOrDeletedRequest_CannotChangeStatus(int ticket)
    {
        Assert.Null(await Repository.UpdateStatusAsync(ticket, SupportRequestStatus.InProgress));
        await using var check = fixture.CreateContext();
        Assert.Equal(SupportRequestStatus.Closed, (await check.SupportRequests.SingleAsync(r => r.Id == 4)).Status);
        Assert.Equal(Timestamp, (await check.SupportRequests.SingleAsync(r => r.Id == 4)).UpdatedAt);
    }

    [Fact]
    public async Task DeleteAndMarkRead_RespectExistenceAndOwnerAndPreserveReplyHistory()
    {
        var repository = Repository;
        Assert.False(await repository.SoftDeleteAsync(999));
        Assert.Equal(1, await repository.GetUnreadCountForUserAsync(1));
        await repository.MarkRepliesAsReadAsync(1, 2);
        Assert.Equal(1, await repository.GetUnreadCountForUserAsync(1));
        await repository.MarkRepliesAsReadAsync(999, 1);
        await repository.MarkRepliesAsReadAsync(1, 1);
        Assert.Equal(0, await repository.GetUnreadCountForUserAsync(1));
        Assert.Equal(1, await repository.GetUnreadCountForUserAsync(2));
        var start = DateTime.UtcNow;
        Assert.True(await repository.SoftDeleteAsync(6));
        Assert.Equal(0, await repository.GetUnreadCountForUserAsync(2));
        await using var check = fixture.CreateContext();
        Assert.Equal(5, await check.SupportReplies.CountAsync());
        Assert.False((await check.SupportReplies.SingleAsync(r => r.Id == 2)).IsRead);
        var deleted = await check.SupportRequests.SingleAsync(r => r.Id == 6);
        Assert.True(deleted.IsDeleted);
        Assert.InRange(deleted.DeletedAt!.Value, start, DateTime.UtcNow);
    }
}
