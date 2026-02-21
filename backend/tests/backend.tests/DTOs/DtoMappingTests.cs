using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.DTOs;

[Trait("Category", "Unit")]
public class DtoMappingTests
{
    #region SupportRequestDto Tests

    [Fact]
    public void SupportRequestDto_FromEntity_MapsAllFields()
    {
        // Arrange
        var entity = new SupportRequest
        {
            Id = 123,
            UserId = 456,
            Email = "test@example.com",
            Subject = "Test Subject",
            Description = "Test Description",
            Status = SupportRequestStatus.InProgress,
            CreatedAt = new DateTime(2024, 1, 15, 10, 30, 0),
            UpdatedAt = new DateTime(2024, 1, 16, 14, 45, 0),
            IsDeleted = false,
            Replies = new List<SupportReply>()
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity);

        // Assert
        Assert.Equal(123, dto.SupportRequestId);
        Assert.Equal(456, dto.UserId);
        Assert.Equal("test@example.com", dto.Email);
        Assert.Equal("Test Subject", dto.Subject);
        Assert.Equal("Test Description", dto.Description);
        Assert.Equal("InProgress", dto.Status);
        Assert.Equal(new DateTime(2024, 1, 15, 10, 30, 0), dto.CreatedAt);
        Assert.Equal(new DateTime(2024, 1, 16, 14, 45, 0), dto.UpdatedAt);
        Assert.False(dto.IsDeleted);
    }

    [Fact]
    public void SupportRequestDto_FromEntity_CountsReplies()
    {
        // Arrange
        var entity = new SupportRequest
        {
            Id = 1,
            Email = "test@example.com",
            Subject = "Subject",
            Description = "Desc",
            Status = SupportRequestStatus.Open,
            Replies = new List<SupportReply>
            {
                new() { Id = 1, Message = "Reply 1", IsFromAdmin = false, IsRead = false },
                new() { Id = 2, Message = "Reply 2", IsFromAdmin = true, IsRead = false },
                new() { Id = 3, Message = "Reply 3", IsFromAdmin = true, IsRead = true }
            }
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity);

        // Assert
        Assert.Equal(3, dto.ReplyCount);
        Assert.Equal(1, dto.UnreadCount); // Only unread admin replies
    }

    [Fact]
    public void SupportRequestDto_FromEntity_IncludesRepliesWhenRequested()
    {
        // Arrange
        var entity = new SupportRequest
        {
            Id = 1,
            Email = "test@example.com",
            Subject = "Subject",
            Description = "Desc",
            Status = SupportRequestStatus.Open,
            Replies = new List<SupportReply>
            {
                new() { Id = 2, Message = "Second", CreatedAt = DateTime.UtcNow.AddHours(1), SupportRequestId = 1 },
                new() { Id = 1, Message = "First", CreatedAt = DateTime.UtcNow, SupportRequestId = 1 }
            }
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity, includeReplies: true);

        // Assert
        Assert.Equal(2, dto.Replies.Count);
        Assert.Equal("First", dto.Replies[0].Message); // Ordered by CreatedAt
        Assert.Equal("Second", dto.Replies[1].Message);
    }

    [Fact]
    public void SupportRequestDto_FromEntity_ExcludesRepliesByDefault()
    {
        // Arrange
        var entity = new SupportRequest
        {
            Id = 1,
            Email = "test@example.com",
            Subject = "Subject",
            Description = "Desc",
            Status = SupportRequestStatus.Open,
            Replies = new List<SupportReply>
            {
                new() { Id = 1, Message = "Reply" }
            }
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity);

        // Assert
        Assert.Empty(dto.Replies);
        Assert.Equal(1, dto.ReplyCount); // Count is still correct
    }

    [Fact]
    public void SupportRequestDto_FromEntity_HandlesNullReplies()
    {
        // Arrange
        var entity = new SupportRequest
        {
            Id = 1,
            Email = "test@example.com",
            Subject = "Subject",
            Description = "Desc",
            Status = SupportRequestStatus.Open,
            Replies = null!
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity);

        // Assert
        Assert.Equal(0, dto.ReplyCount);
        Assert.Equal(0, dto.UnreadCount);
    }

    [Fact]
    public void SupportRequestDto_FromEntity_HandlesNullUserId()
    {
        // Arrange (anonymous request)
        var entity = new SupportRequest
        {
            Id = 1,
            UserId = null,
            Email = "anonymous@example.com",
            Subject = "Subject",
            Description = "Desc",
            Status = SupportRequestStatus.Open
        };

        // Act
        var dto = SupportRequestDto.FromEntity(entity);

        // Assert
        Assert.Null(dto.UserId);
    }

    #endregion

    #region SupportReplyDto Tests

    [Fact]
    public void SupportReplyDto_FromEntity_MapsAllFields()
    {
        // Arrange
        var entity = new SupportReply
        {
            Id = 789,
            SupportRequestId = 123,
            UserId = 456,
            IsFromAdmin = true,
            Message = "Admin reply message",
            CreatedAt = new DateTime(2024, 2, 20, 9, 15, 0),
            IsRead = true
        };

        // Act
        var dto = SupportReplyDto.FromEntity(entity);

        // Assert
        Assert.Equal(789, dto.SupportReplyId);
        Assert.Equal(123, dto.SupportRequestId);
        Assert.Equal(456, dto.UserId);
        Assert.True(dto.IsFromAdmin);
        Assert.Equal("Admin reply message", dto.Message);
        Assert.Equal(new DateTime(2024, 2, 20, 9, 15, 0), dto.CreatedAt);
        Assert.True(dto.IsRead);
    }

    [Fact]
    public void SupportReplyDto_FromEntity_HandlesNullUserId()
    {
        // Arrange
        var entity = new SupportReply
        {
            Id = 1,
            SupportRequestId = 1,
            UserId = default, // null for nullable int
            IsFromAdmin = false,
            Message = "Message",
            CreatedAt = DateTime.UtcNow
        };

        // Act
        var dto = SupportReplyDto.FromEntity(entity);

        // Assert
        Assert.Null(dto.UserId);
    }

    #endregion

    #region WorkspaceUserResponse Tests

    [Fact]
    public void WorkspaceUserResponse_FromUser_MapsLinkedUser()
    {
        // Arrange
        var user = new User
        {
            Id = 100,
            Email = "user@example.com",
            IdentityProvider = IdentityProvider.Microsoft,
            ProviderSubjectId = "sub-123",
            CreatedAt = new DateTime(2024, 3, 10)
        };

        // Act
        var response = WorkspaceUserResponse.FromUser(user, WorkspaceRole.WorkspaceAdmin);

        // Assert
        Assert.Equal(100, response.UserId);
        Assert.Equal("user@example.com", response.Email);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, response.WorkspaceRole);
        Assert.True(response.IsLinked);
        Assert.Equal("Microsoft", response.IdentityProvider);
        Assert.Equal(new DateTime(2024, 3, 10), response.CreatedAt);
    }

    [Fact]
    public void WorkspaceUserResponse_FromUser_MapsUnlinkedUser()
    {
        // Arrange
        var user = new User
        {
            Id = 101,
            Email = "invited@example.com",
            IdentityProvider = IdentityProvider.None,
            ProviderSubjectId = "",
            CreatedAt = new DateTime(2024, 4, 15)
        };

        // Act
        var response = WorkspaceUserResponse.FromUser(user, WorkspaceRole.Normal);

        // Assert
        Assert.Equal(101, response.UserId);
        Assert.Equal("invited@example.com", response.Email);
        Assert.Equal(WorkspaceRole.Normal, response.WorkspaceRole);
        Assert.False(response.IsLinked);
        Assert.Null(response.IdentityProvider);
    }

    [Fact]
    public void WorkspaceUserResponse_FromWorkspaceUser_MapsAllFields()
    {
        // Arrange
        var workspaceUser = new WorkspaceUser
        {
            UserId = 200,
            WorkspaceId = 1,
            WorkspaceRole = WorkspaceRole.WorkspaceAdmin,
            CreatedAt = new DateTime(2024, 5, 20),
            User = new User
            {
                Id = 200,
                Email = "admin@example.com",
                IdentityProvider = IdentityProvider.Google,
                ProviderSubjectId = "google-sub-456"
            }
        };

        // Act
        var response = WorkspaceUserResponse.FromWorkspaceUser(workspaceUser);

        // Assert
        Assert.Equal(200, response.UserId);
        Assert.Equal("admin@example.com", response.Email);
        Assert.Equal(WorkspaceRole.WorkspaceAdmin, response.WorkspaceRole);
        Assert.True(response.IsLinked);
        Assert.Equal("Google", response.IdentityProvider);
        Assert.Equal(new DateTime(2024, 5, 20), response.CreatedAt);
    }

    [Fact]
    public void WorkspaceUserResponse_FromWorkspaceUser_HandlesUnlinkedUser()
    {
        // Arrange
        var workspaceUser = new WorkspaceUser
        {
            UserId = 201,
            WorkspaceId = 1,
            WorkspaceRole = WorkspaceRole.Normal,
            CreatedAt = new DateTime(2024, 6, 25),
            User = new User
            {
                Id = 201,
                Email = "pending@example.com",
                IdentityProvider = IdentityProvider.None,
                ProviderSubjectId = null
            }
        };

        // Act
        var response = WorkspaceUserResponse.FromWorkspaceUser(workspaceUser);

        // Assert
        Assert.Equal(201, response.UserId);
        Assert.False(response.IsLinked);
        Assert.Null(response.IdentityProvider);
    }

    #endregion

    #region CreateItemRequest Tests

    [Fact]
    public void CreateItemRequest_ToItem_SetsAllProperties()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Test Item",
            Summary = "Item summary",
            Description = "Item description",
            CollectionId = 10,
            CategoryId = 5,
            UserFlag = UserFlag.Want,
            Visibility = Visibility.Public
        };

        // Act
        var item = request.ToItem(workspaceId: 1);

        // Assert
        Assert.Equal("Test Item", item.Name);
        Assert.Equal("Item summary", item.Summary);
        Assert.Equal("Item description", item.Description);
        Assert.Equal(10, item.CollectionId);
        Assert.Equal(5, item.CategoryId);
        Assert.Equal(UserFlag.Want, item.UserFlag);
        Assert.Equal(Visibility.Public, item.Visibility);
        Assert.Equal(1, item.WorkspaceId);
    }

    [Fact]
    public void CreateItemRequest_ToItem_SetsDefaultsForOptionalFields()
    {
        // Arrange
        var request = new CreateItemRequest
        {
            Name = "Minimal Item",
            CollectionId = 1
        };

        // Act
        var item = request.ToItem(workspaceId: 2);

        // Assert
        Assert.Equal("Minimal Item", item.Name);
        Assert.Equal(string.Empty, item.Description);
        Assert.Null(item.CategoryId);
        Assert.Equal(UserFlag.Have, item.UserFlag);
        Assert.Equal(Visibility.Default, item.Visibility);
        Assert.Equal(2, item.WorkspaceId);
    }

    #endregion

    #region UpdateItemRequest Tests

    [Fact]
    public void UpdateItemRequest_ToItem_SetsIdAndProperties()
    {
        // Arrange
        var request = new UpdateItemRequest
        {
            Name = "Updated Item",
            Summary = "Updated summary",
            Description = "Updated description",
            CollectionId = 15,
            CategoryId = 8,
            UserFlag = UserFlag.TradeOrSell,
            Visibility = Visibility.Private
        };

        // Act
        var item = request.ToItem(id: 123, workspaceId: 3);

        // Assert
        Assert.Equal(123, item.Id);
        Assert.Equal("Updated Item", item.Name);
        Assert.Equal("Updated summary", item.Summary);
        Assert.Equal("Updated description", item.Description);
        Assert.Equal(15, item.CollectionId);
        Assert.Equal(8, item.CategoryId);
        Assert.Equal(UserFlag.TradeOrSell, item.UserFlag);
        Assert.Equal(Visibility.Private, item.Visibility);
        Assert.Equal(3, item.WorkspaceId);
    }

    #endregion
}
