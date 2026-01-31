using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Tests.Integration.Data;

[Trait("Category", "Integration")]
public class SupportRepositoryTests : IDisposable
{
    private readonly AppDbContext _context;
    private readonly SupportRepository _repository;

    public SupportRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new AppDbContext(options);
        _repository = new SupportRepository(_context);
    }

    public void Dispose()
    {
        _context.Dispose();
    }

    #region CreateRequestAsync Tests

    [Fact]
    public async Task CreateRequestAsync_CreatesRequest_WithTimestamps()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.Open
        };

        // Act
        var result = await _repository.CreateRequestAsync(request);

        // Assert
        Assert.NotEqual(0, result.Id);
        Assert.NotEqual(default, result.CreatedAt);
        Assert.NotEqual(default, result.UpdatedAt);
        // Allow small time difference due to precision
        Assert.True(Math.Abs((result.CreatedAt - result.UpdatedAt).TotalMilliseconds) < 100);
    }

    #endregion

    #region GetRequestsForUserAsync Tests

    [Fact]
    public async Task GetRequestsForUserAsync_ReturnsUserRequests_WithReplyCount()
    {
        // Arrange
        var user1Request = new SupportRequest
        {
            UserId = 1,
            Email = "user1@example.com",
            Subject = "User 1 Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        var user2Request = new SupportRequest
        {
            UserId = 2,
            Email = "user2@example.com",
            Subject = "User 2 Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.SupportRequests.AddRangeAsync(user1Request, user2Request);
        await _context.SaveChangesAsync();

        // Add replies to user1's request
        var replies = new List<SupportReply>
        {
            new() { SupportRequestId = user1Request.Id, Message = "Reply 1", IsFromAdmin = true, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = user1Request.Id, Message = "Reply 2", IsFromAdmin = false, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = user1Request.Id, Message = "Reply 3", IsFromAdmin = true, CreatedAt = DateTime.UtcNow }
        };
        await _context.SupportReplies.AddRangeAsync(replies);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetRequestsForUserAsync(1)).ToList();

        // Assert
        Assert.Single(result);
        Assert.Equal("User 1 Request", result[0].Subject);
        Assert.NotNull(result[0].Replies);
        Assert.Equal(3, result[0].Replies.Count);
    }

    [Fact]
    public async Task GetRequestsForUserAsync_ExcludesDeletedRequests_ByDefault()
    {
        // Arrange
        var activeRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Active Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = false
        };
        var deletedRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Deleted Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = true,
            DeletedAt = DateTime.UtcNow
        };

        await _context.SupportRequests.AddRangeAsync(activeRequest, deletedRequest);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetRequestsForUserAsync(1)).ToList();

        // Assert
        Assert.Single(result);
        Assert.Equal("Active Request", result[0].Subject);
    }

    [Fact]
    public async Task GetRequestsForUserAsync_IncludesDeletedRequests_WhenRequested()
    {
        // Arrange
        var activeRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Active Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = false
        };
        var deletedRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Deleted Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = true,
            DeletedAt = DateTime.UtcNow
        };

        await _context.SupportRequests.AddRangeAsync(activeRequest, deletedRequest);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetRequestsForUserAsync(1, includeDeleted: true)).ToList();

        // Assert
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public async Task GetRequestsForUserAsync_ReturnsOrderedByUpdatedAtDescending()
    {
        // Arrange
        var oldRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Old Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow.AddDays(-2),
            UpdatedAt = DateTime.UtcNow.AddDays(-2)
        };
        var newRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "New Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.SupportRequests.AddRangeAsync(oldRequest, newRequest);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetRequestsForUserAsync(1)).ToList();

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Equal("New Request", result[0].Subject);
        Assert.Equal("Old Request", result[1].Subject);
    }

    #endregion

    #region GetAllRequestsAsync Tests

    [Fact]
    public async Task GetAllRequestsAsync_ReturnsAllRequests_WithReplies()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        await _context.SupportRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        var replies = new List<SupportReply>
        {
            new() { SupportRequestId = request.Id, Message = "Reply 1", IsFromAdmin = true, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = request.Id, Message = "Reply 2", IsFromAdmin = false, CreatedAt = DateTime.UtcNow }
        };
        await _context.SupportReplies.AddRangeAsync(replies);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllRequestsAsync()).ToList();

        // Assert
        Assert.Single(result);
        Assert.NotNull(result[0].Replies);
        Assert.Equal(2, result[0].Replies.Count);
    }

    [Fact]
    public async Task GetAllRequestsAsync_FiltersbyStatus()
    {
        // Arrange
        var openRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Open Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        var closedRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Closed Request",
            Description = "Description",
            Status = SupportRequestStatus.Closed,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        await _context.SupportRequests.AddRangeAsync(openRequest, closedRequest);
        await _context.SaveChangesAsync();

        // Act
        var result = (await _repository.GetAllRequestsAsync(status: SupportRequestStatus.Open)).ToList();

        // Assert
        Assert.Single(result);
        Assert.Equal("Open Request", result[0].Subject);
    }

    #endregion

    #region AddReplyAsync Tests

    [Fact]
    public async Task AddReplyAsync_CreatesReply_AndUpdatesRequestTimestamp()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow.AddHours(-1),
            UpdatedAt = DateTime.UtcNow.AddHours(-1)
        };
        await _context.SupportRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        var originalUpdatedAt = request.UpdatedAt;

        var reply = new SupportReply
        {
            SupportRequestId = request.Id,
            Message = "Test Reply",
            IsFromAdmin = false,
            UserId = 1
        };

        // Act
        var result = await _repository.AddReplyAsync(reply);

        // Assert
        Assert.NotEqual(0, result.Id);
        Assert.NotEqual(default, result.CreatedAt);

        // Verify request UpdatedAt was updated
        var updatedRequest = await _context.SupportRequests.FindAsync(request.Id);
        Assert.NotNull(updatedRequest);
        Assert.True(updatedRequest.UpdatedAt > originalUpdatedAt);
    }

    #endregion

    #region GetUnreadCountForUserAsync Tests

    [Fact]
    public async Task GetUnreadCountForUserAsync_ReturnsUnreadAdminReplies()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        await _context.SupportRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        var replies = new List<SupportReply>
        {
            new() { SupportRequestId = request.Id, Message = "Admin Reply 1", IsFromAdmin = true, IsRead = false, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = request.Id, Message = "Admin Reply 2", IsFromAdmin = true, IsRead = true, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = request.Id, Message = "User Reply", IsFromAdmin = false, IsRead = false, CreatedAt = DateTime.UtcNow }
        };
        await _context.SupportReplies.AddRangeAsync(replies);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetUnreadCountForUserAsync(1);

        // Assert
        Assert.Equal(1, result); // Only 1 unread admin reply
    }

    [Fact]
    public async Task GetUnreadCountForUserAsync_ExcludesDeletedRequests()
    {
        // Arrange
        var deletedRequest = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Deleted Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            IsDeleted = true,
            DeletedAt = DateTime.UtcNow
        };
        await _context.SupportRequests.AddAsync(deletedRequest);
        await _context.SaveChangesAsync();

        var reply = new SupportReply
        {
            SupportRequestId = deletedRequest.Id,
            Message = "Admin Reply",
            IsFromAdmin = true,
            IsRead = false,
            CreatedAt = DateTime.UtcNow
        };
        await _context.SupportReplies.AddAsync(reply);
        await _context.SaveChangesAsync();

        // Act
        var result = await _repository.GetUnreadCountForUserAsync(1);

        // Assert
        Assert.Equal(0, result); // Deleted requests shouldn't count
    }

    #endregion

    #region MarkRepliesAsReadAsync Tests

    [Fact]
    public async Task MarkRepliesAsReadAsync_MarksAdminRepliesAsRead()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        await _context.SupportRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        var replies = new List<SupportReply>
        {
            new() { SupportRequestId = request.Id, Message = "Admin Reply 1", IsFromAdmin = true, IsRead = false, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = request.Id, Message = "Admin Reply 2", IsFromAdmin = true, IsRead = false, CreatedAt = DateTime.UtcNow },
            new() { SupportRequestId = request.Id, Message = "User Reply", IsFromAdmin = false, IsRead = false, CreatedAt = DateTime.UtcNow }
        };
        await _context.SupportReplies.AddRangeAsync(replies);
        await _context.SaveChangesAsync();

        // Act
        await _repository.MarkRepliesAsReadAsync(request.Id, 1);

        // Assert
        var updatedReplies = await _context.SupportReplies.Where(r => r.SupportRequestId == request.Id).ToListAsync();
        Assert.Equal(2, updatedReplies.Count(r => r.IsFromAdmin && r.IsRead));
        Assert.Single(updatedReplies, r => !r.IsFromAdmin && !r.IsRead); // User reply unchanged
    }

    [Fact]
    public async Task MarkRepliesAsReadAsync_DoesNothing_ForOtherUsersRequests()
    {
        // Arrange
        var request = new SupportRequest
        {
            UserId = 1,
            Email = "test@example.com",
            Subject = "Test Request",
            Description = "Description",
            Status = SupportRequestStatus.Open,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        await _context.SupportRequests.AddAsync(request);
        await _context.SaveChangesAsync();

        var reply = new SupportReply
        {
            SupportRequestId = request.Id,
            Message = "Admin Reply",
            IsFromAdmin = true,
            IsRead = false,
            CreatedAt = DateTime.UtcNow
        };
        await _context.SupportReplies.AddAsync(reply);
        await _context.SaveChangesAsync();

        // Act - Try to mark as read as a different user
        await _repository.MarkRepliesAsReadAsync(request.Id, userId: 999);

        // Assert - Should still be unread
        var updatedReply = await _context.SupportReplies.FindAsync(reply.Id);
        Assert.NotNull(updatedReply);
        Assert.False(updatedReply.IsRead);
    }

    #endregion
}
