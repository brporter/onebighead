using OneBigHead.Server.Models;

namespace OneBigHead.Server.Data;

public interface IWorkspaceRepository
{
    Task<Workspace?> GetByIdAsync(int id);
    Task UpdateAsync(Workspace workspace);
    Task CreateAsync(Workspace workspace);
}
