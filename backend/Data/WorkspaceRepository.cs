using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class WorkspaceRepository : IWorkspaceRepository
{
    private readonly AppDbContext _context;

    public WorkspaceRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<Workspace?> GetByIdAsync(int id)
    {
        return await _context.Workspaces.FirstOrDefaultAsync(t => t.Id == id);
    }

    public async Task UpdateAsync(Workspace workspace)
    {
        _context.Workspaces.Update(workspace);
        await _context.SaveChangesAsync();
    }

    public async Task CreateAsync(Workspace workspace)
    {
        _context.Workspaces.Add(workspace);
        await _context.SaveChangesAsync();
    }
}
