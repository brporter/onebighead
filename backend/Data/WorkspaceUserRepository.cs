using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace OneBigHead.Server.Data;

public class WorkspaceUserRepository : IWorkspaceUserRepository
{
    private readonly AppDbContext _context;

    public WorkspaceUserRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<WorkspaceUser?> GetMembershipAsync(int userId, int workspaceId)
    {
        return await _context.WorkspaceUsers
            .Include(tu => tu.Workspace)
            .Include(tu => tu.User)
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.WorkspaceId == workspaceId);
    }

    public async Task<IEnumerable<WorkspaceUser>> GetByUserIdAsync(int userId)
    {
        return await _context.WorkspaceUsers
            .Include(tu => tu.Workspace)
            .Where(tu => tu.UserId == userId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<IEnumerable<WorkspaceUser>> GetByWorkspaceIdAsync(int workspaceId)
    {
        return await _context.WorkspaceUsers
            .Include(tu => tu.User)
            .Where(tu => tu.WorkspaceId == workspaceId)
            .OrderBy(tu => tu.CreatedAt)
            .ToListAsync();
    }

    public async Task<WorkspaceUser> CreateAsync(int userId, int workspaceId, WorkspaceRole role)
    {
        var workspaceUser = new WorkspaceUser
        {
            UserId = userId,
            WorkspaceId = workspaceId,
            WorkspaceRole = role,
            CreatedAt = DateTime.UtcNow
        };

        _context.WorkspaceUsers.Add(workspaceUser);
        await _context.SaveChangesAsync();

        // Load related entities
        await _context.Entry(workspaceUser).Reference(tu => tu.Workspace).LoadAsync();
        await _context.Entry(workspaceUser).Reference(tu => tu.User).LoadAsync();

        return workspaceUser;
    }

    public async Task<bool> UpdateRoleAsync(int userId, int workspaceId, WorkspaceRole role)
    {
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.WorkspaceId == workspaceId);

        if (workspaceUser == null)
        {
            return false;
        }

        workspaceUser.WorkspaceRole = role;
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(int userId, int workspaceId)
    {
        var workspaceUser = await _context.WorkspaceUsers
            .FirstOrDefaultAsync(wu => wu.UserId == userId && wu.WorkspaceId == workspaceId);

        if (workspaceUser == null)
        {
            return false;
        }

        _context.WorkspaceUsers.Remove(workspaceUser);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<int> CountAdminsInWorkspaceAsync(int workspaceId)
    {
        return await _context.WorkspaceUsers
            .CountAsync(tu => tu.WorkspaceId == workspaceId && tu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin);
    }

    public async Task<int> CountMembersInWorkspaceAsync(int workspaceId)
    {
        return await _context.WorkspaceUsers
            .CountAsync(tu => tu.WorkspaceId == workspaceId);
    }

    public async Task<int> CountUserMembershipsAsync(int userId)
    {
        return await _context.WorkspaceUsers
            .CountAsync(tu => tu.UserId == userId);
    }

    public async Task<AdminCheckResult> UpdateRoleWithAdminCheckAsync(int userId, int workspaceId, WorkspaceRole newRole)
    {
        // Use serializable isolation to prevent race conditions when checking/updating admin count
        await using var transaction = await _context.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);

        try
        {
            var workspaceUser = await _context.WorkspaceUsers
                .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.WorkspaceId == workspaceId);

            if (workspaceUser == null)
            {
                await transaction.RollbackAsync();
                return AdminCheckResult.UserNotFound;
            }

            // Check if demoting from admin to non-admin
            if (workspaceUser.WorkspaceRole == WorkspaceRole.WorkspaceAdmin && newRole != WorkspaceRole.WorkspaceAdmin)
            {
                var adminCount = await _context.WorkspaceUsers
                    .CountAsync(tu => tu.WorkspaceId == workspaceId && tu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin);

                if (adminCount <= 1)
                {
                    await transaction.RollbackAsync();
                    return AdminCheckResult.WouldRemoveLastAdmin;
                }
            }

            workspaceUser.WorkspaceRole = newRole;
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();

            return AdminCheckResult.Success;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }

    public async Task<AdminCheckResult> DeleteWithAdminCheckAsync(int userId, int workspaceId)
    {
        // Use serializable isolation to prevent race conditions when checking/deleting admin
        await using var transaction = await _context.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable);

        try
        {
            var workspaceUser = await _context.WorkspaceUsers
                .FirstOrDefaultAsync(tu => tu.UserId == userId && tu.WorkspaceId == workspaceId);

            if (workspaceUser == null)
            {
                await transaction.RollbackAsync();
                return AdminCheckResult.UserNotFound;
            }

            // Check if removing an admin
            if (workspaceUser.WorkspaceRole == WorkspaceRole.WorkspaceAdmin)
            {
                var adminCount = await _context.WorkspaceUsers
                    .CountAsync(tu => tu.WorkspaceId == workspaceId && tu.WorkspaceRole == WorkspaceRole.WorkspaceAdmin);

                if (adminCount <= 1)
                {
                    await transaction.RollbackAsync();
                    return AdminCheckResult.WouldRemoveLastAdmin;
                }
            }

            _context.WorkspaceUsers.Remove(workspaceUser);
            await _context.SaveChangesAsync();
            await transaction.CommitAsync();

            return AdminCheckResult.Success;
        }
        catch
        {
            await transaction.RollbackAsync();
            throw;
        }
    }
}
