using OneBigHead.Server.DTOs;
using OneBigHead.Server.Models;
using OneBigHead.Server.Services.Accounts;

namespace OneBigHead.Server.Tests.Services;

[Trait("Category", "Unit")]
public class AccountDeletionPolicyTests
{
    [Fact]
    public void Preview_DescribesAllMembershipKindsAndOrdersEligibleRecipients()
    {
        var user = new User { Id = 1, Email = "owner@example.test" };
        AddWorkspace(user, 4, WorkspaceRole.Normal, (2, WorkspaceRole.WorkspaceAdmin, false));
        AddWorkspace(user, 3, WorkspaceRole.WorkspaceAdmin, (2, WorkspaceRole.WorkspaceAdmin, false));
        AddWorkspace(user, 2, WorkspaceRole.WorkspaceAdmin,
            (2, WorkspaceRole.WorkspaceAdmin, true), (4, WorkspaceRole.Normal, false), (3, WorkspaceRole.Normal, false));
        AddWorkspace(user, 1, WorkspaceRole.Normal);
        AddWorkspace(user, 5, WorkspaceRole.WorkspaceAdmin).IsDeleted = true;
        var preview = AccountDeletionPolicy.Describe(user);
        Assert.Equal(user.Id, preview.UserId);
        Assert.Equal(user.Email, preview.Email);
        Assert.Equal(new[] { 1, 2, 3, 4 }, preview.WorkspaceMemberships.Select(m => m.WorkspaceId));
        Assert.Equal(2, preview.WorkspacesRequiringAction);
        Assert.False(preview.CanDeleteImmediately);
        var sole = preview.WorkspaceMemberships[0];
        Assert.True(sole.IsOnlyUser);
        Assert.False(sole.IsOnlyAdmin);
        Assert.Equal(DeletionBlockerReason.SoleUser, sole.BlockerReason);
        Assert.Equal(WorkspaceRole.Normal, sole.Role);
        Assert.Equal("Workspace 1", sole.WorkspaceName);
        var admin = preview.WorkspaceMemberships[1];
        Assert.False(admin.IsOnlyUser);
        Assert.True(admin.IsOnlyAdmin);
        Assert.Equal(4, admin.UserCount);
        Assert.Equal(new[] { 3, 4 }, admin.OtherUsers.Select(u => u.UserId));
        Assert.All(admin.OtherUsers, u => Assert.Equal("member@example.test", u.Email));
        Assert.All(preview.WorkspaceMemberships.Skip(2), m =>
        {
            Assert.True(m.CanLeave);
            Assert.Empty(m.OtherUsers);
            Assert.Equal(DeletionBlockerReason.None, m.BlockerReason);
        });
    }

    [Fact]
    public void NoMemberships_RequiresNoActionAndAcceptsCaseInsensitiveEmail()
    {
        var preview = AccountDeletionPolicy.Describe(new User { Id = 1, Email = "Owner@example.test" });
        Assert.Empty(preview.WorkspaceMemberships);
        Assert.True(preview.CanDeleteImmediately);
        Assert.Equal(0, preview.WorkspacesRequiringAction);
        Assert.Null(AccountDeletionPolicy.Validate(preview, new() { ConfirmEmail = "OWNER@example.test" }));
        Assert.Contains("Email confirmation", AccountDeletionPolicy.Validate(preview, new() { ConfirmEmail = "other@example.test" }));
    }

    [Theory]
    [InlineData("missing", "Missing action")]
    [InlineData("duplicate", "only one action")]
    [InlineData("null-action", "valid action")]
    [InlineData("foreign", "membership changed")]
    [InlineData("unnecessary", "membership changed")]
    [InlineData("deleted-workspace", "membership changed")]
    [InlineData("sole-transfer", "must be deleted")]
    [InlineData("sole-target", "must be deleted")]
    [InlineData("admin-delete", "must be transferred")]
    [InlineData("admin-no-target", "must be transferred")]
    [InlineData("self", "active member")]
    [InlineData("absent", "active member")]
    [InlineData("deleted-recipient", "active member")]
    public void InvalidPlan_IsRejectedBeforeAnyEntityChanges(string scenario, string message)
    {
        var user = new User { Id = 1, Email = "owner@example.test" };
        var sole = AddWorkspace(user, 1, WorkspaceRole.WorkspaceAdmin);
        var shared = AddWorkspace(user, 2, WorkspaceRole.WorkspaceAdmin,
            (2, WorkspaceRole.Normal, false), (3, WorkspaceRole.Normal, true));
        AddWorkspace(user, 3, WorkspaceRole.Normal, (2, WorkspaceRole.WorkspaceAdmin, false));
        AddWorkspace(user, 4, WorkspaceRole.WorkspaceAdmin).IsDeleted = true;
        var actions = new List<WorkspaceActionRequest>
        {
            new() { WorkspaceId = 1, Action = WorkspaceActionType.Delete },
            new() { WorkspaceId = 2, Action = WorkspaceActionType.Transfer, TransferToUserId = 2 }
        };
        switch (scenario)
        {
            case "missing": actions.RemoveAt(1); break;
            case "duplicate": actions.Add(actions[0]); break;
            case "null-action": actions.Add(null!); break;
            case "foreign": actions.Add(new() { WorkspaceId = 999 }); break;
            case "unnecessary": actions.Add(new() { WorkspaceId = 3 }); break;
            case "deleted-workspace": actions.Add(new() { WorkspaceId = 4 }); break;
            case "sole-transfer": actions[0].Action = WorkspaceActionType.Transfer; break;
            case "sole-target": actions[0].TransferToUserId = 2; break;
            case "admin-delete": actions[1].Action = WorkspaceActionType.Delete; break;
            case "admin-no-target": actions[1].TransferToUserId = null; break;
            case "self": actions[1].TransferToUserId = 1; break;
            case "absent": actions[1].TransferToUserId = 999; break;
            case "deleted-recipient": actions[1].TransferToUserId = 3; break;
        }
        Assert.Contains(message, AccountDeletionPolicy.Validate(AccountDeletionPolicy.Describe(user),
            new() { ConfirmEmail = user.Email, WorkspaceActions = actions }));
        Assert.False(sole.IsDeleted);
        Assert.Equal(WorkspaceRole.Normal, shared.WorkspaceUsers.Single(m => m.UserId == 2).WorkspaceRole);
        Assert.Equal(4, user.WorkspaceMemberships.Count);
    }

    [Fact]
    public void ValidPlan_AcceptsSoleWorkspaceDeletionAndActiveMemberTransfer()
    {
        var user = new User { Id = 1, Email = "owner@example.test" };
        AddWorkspace(user, 1, WorkspaceRole.WorkspaceAdmin);
        AddWorkspace(user, 2, WorkspaceRole.WorkspaceAdmin, (2, WorkspaceRole.Normal, false));
        Assert.Null(AccountDeletionPolicy.Validate(AccountDeletionPolicy.Describe(user), new()
        {
            ConfirmEmail = user.Email,
            WorkspaceActions = [new() { WorkspaceId = 1, Action = WorkspaceActionType.Delete },
                new() { WorkspaceId = 2, Action = WorkspaceActionType.Transfer, TransferToUserId = 2 }]
        }));
    }

    private static Workspace AddWorkspace(User user, int id, WorkspaceRole role,
        params (int Id, WorkspaceRole Role, bool Deleted)[] others)
    {
        var workspace = new Workspace { Id = id, Name = $"Workspace {id}" };
        var own = new WorkspaceUser { User = user, UserId = user.Id, Workspace = workspace, WorkspaceId = id, WorkspaceRole = role };
        user.WorkspaceMemberships.Add(own);
        workspace.WorkspaceUsers.Add(own);
        foreach (var other in others)
            workspace.WorkspaceUsers.Add(new()
            {
                UserId = other.Id, WorkspaceId = id, Workspace = workspace, WorkspaceRole = other.Role,
                User = new User { Id = other.Id, Email = "member@example.test", IsDeleted = other.Deleted }
            });
        return workspace;
    }
}
