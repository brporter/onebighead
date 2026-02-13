using System.Net;
using System.Net.Http.Json;
using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;

namespace OneBigHead.Server.Tests.Integration;

[Trait("Category", "Integration")]
public class SupportControllerTests : IntegrationTestBase
{
    public SupportControllerTests(CustomWebApplicationFactory factory)
        : base(factory)
    {
    }

    #region POST /api/support (Anonymous)

    [Fact]
    public async Task CreateSupportRequest_Anonymous_ValidRequest_Creates()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();
        var request = new CreateSupportRequestDto
        {
            Email = "anonymous@example.com",
            Subject = "Help Request",
            Description = "I need help with something"
        };

        // Act
        var response = await anonClient.PostAsJsonAsync("/api/support", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<SupportRequestDto>(response);
        Assert.NotNull(created);
        Assert.Equal("anonymous@example.com", created.Email);
        Assert.Equal("Help Request", created.Subject);
        Assert.Null(created.UserId); // Anonymous request has no user
    }

    [Fact]
    public async Task CreateSupportRequest_Authenticated_IncludesUserInfo()
    {
        // Arrange
        var request = new CreateSupportRequestDto
        {
            Subject = "Authenticated Help",
            Description = "Help from logged in user"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/support", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await DeserializeResponseAsync<SupportRequestDto>(response);
        Assert.NotNull(created);
        Assert.Equal(DefaultUserId, created.UserId);
        Assert.Equal(DefaultEmail, created.Email);
    }

    [Fact]
    public async Task CreateSupportRequest_Anonymous_MissingEmail_ReturnsBadRequest()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();
        var request = new CreateSupportRequestDto
        {
            Subject = "No Email",
            Description = "Message without email"
        };

        // Act
        var response = await anonClient.PostAsJsonAsync("/api/support", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    #endregion

    #region GET /api/support (Authenticated)

    [Fact]
    public async Task GetUserSupportRequests_ReturnsOnlyOwnRequests()
    {
        // Arrange - Create a support request first
        var createRequest = new CreateSupportRequestDto
        {
            Subject = "My Request",
            Description = "My description"
        };
        await Client.PostAsJsonAsync("/api/support", createRequest);

        // Act
        var response = await Client.GetAsync("/api/support");

        // Assert
        response.EnsureSuccessStatusCode();
        var requests = await DeserializeResponseAsync<List<SupportRequestDto>>(response);
        Assert.NotNull(requests);
        Assert.All(requests, r => Assert.Equal(DefaultUserId, r.UserId));
    }

    [Fact]
    public async Task GetUserSupportRequests_Unauthenticated_ReturnsUnauthorized()
    {
        // Arrange
        using var anonClient = CreateAnonymousClient();

        // Act
        var response = await anonClient.GetAsync("/api/support");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    #endregion

    #region GET /api/support/{id}

    [Fact]
    public async Task GetSupportRequest_OwnRequest_ReturnsRequestWithReplies()
    {
        // Arrange
        var createRequest = new CreateSupportRequestDto
        {
            Subject = "Get Test",
            Description = "Description"
        };
        var createResponse = await Client.PostAsJsonAsync("/api/support", createRequest);
        var created = await DeserializeResponseAsync<SupportRequestDto>(createResponse);

        // Act
        var response = await Client.GetAsync($"/api/support/{created!.SupportRequestId}");

        // Assert
        response.EnsureSuccessStatusCode();
        var fetched = await DeserializeResponseAsync<SupportRequestDto>(response);
        Assert.Equal("Get Test", fetched!.Subject);
        Assert.NotNull(fetched.Replies);
    }

    [Fact]
    public async Task GetSupportRequest_OtherUserRequest_ReturnsForbidden()
    {
        // Arrange - Create request from another user by seeding directly
        await Factory.SeedDatabaseAsync(context =>
        {
            var otherUser = new User
            {
                Id = 999,
                ActiveWorkspaceId = DefaultWorkspaceId,
                Email = "other@example.com",
                IdentityProvider = IdentityProvider.Microsoft,
                ProviderSubjectId = "other-user"
            };
            context.Users.Add(otherUser);
            context.WorkspaceUsers.Add(new WorkspaceUser
            {
                UserId = 999,
                WorkspaceId = DefaultWorkspaceId,
                WorkspaceRole = WorkspaceRole.Normal
            });

            var request = new SupportRequest
            {
                Id = 5000,
                Email = "other@example.com",
                Subject = "Other User Request",
                Description = "Description",
                UserId = 999,
                Status = SupportRequestStatus.Open
            };
            context.SupportRequests.Add(request);
        });

        // Act
        var response = await Client.GetAsync("/api/support/5000");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    #endregion

    #region POST /api/support/{id}/reply

    [Fact]
    public async Task AddReply_OwnRequest_AddsReply()
    {
        // Arrange
        var createRequest = new CreateSupportRequestDto
        {
            Subject = "Reply Test",
            Description = "Original description"
        };
        var createResponse = await Client.PostAsJsonAsync("/api/support", createRequest);
        var created = await DeserializeResponseAsync<SupportRequestDto>(createResponse);

        var replyRequest = new CreateSupportReplyDto
        {
            Message = "User follow-up message"
        };

        // Act
        var response = await Client.PostAsJsonAsync($"/api/support/{created!.SupportRequestId}/reply", replyRequest);

        // Assert
        response.EnsureSuccessStatusCode();

        // Verify reply was added
        var getResponse = await Client.GetAsync($"/api/support/{created.SupportRequestId}");
        var fetched = await DeserializeResponseAsync<SupportRequestDto>(getResponse);
        Assert.Single(fetched!.Replies);
        Assert.Equal("User follow-up message", fetched.Replies[0].Message);
        Assert.False(fetched.Replies[0].IsFromAdmin);
    }

    #endregion

    #region DELETE /api/support/{id}

    [Fact]
    public async Task DeleteSupportRequest_OwnRequest_SoftDeletes()
    {
        // Arrange
        var createRequest = new CreateSupportRequestDto
        {
            Subject = "To Delete",
            Description = "Will be deleted"
        };
        var createResponse = await Client.PostAsJsonAsync("/api/support", createRequest);
        var created = await DeserializeResponseAsync<SupportRequestDto>(createResponse);

        // Act
        var response = await Client.DeleteAsync($"/api/support/{created!.SupportRequestId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    #endregion

    #region GET /api/support/unread-count

    [Fact]
    public async Task GetUnreadCount_ReturnsCount()
    {
        // Act
        var response = await Client.GetAsync("/api/support/unread-count");

        // Assert
        response.EnsureSuccessStatusCode();
        var result = await DeserializeResponseAsync<SupportUnreadCountDto>(response);
        Assert.NotNull(result);
        Assert.Equal(0, result.UnreadCount);
    }

    #endregion
}
