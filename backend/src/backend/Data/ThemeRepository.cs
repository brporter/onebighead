using OneBigHead.Server.Models;
using Microsoft.EntityFrameworkCore;

namespace OneBigHead.Server.Data;

public class ThemeRepository : IThemeRepository
{
    private readonly IDbContextFactory<AppDbContext> _contextFactory;

    public ThemeRepository(IDbContextFactory<AppDbContext> contextFactory)
    {
        _contextFactory = contextFactory;
    }

    public async Task<IEnumerable<CollectionTheme>> GetAllAsync()
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.CollectionThemes
            .AsNoTracking()
            .Include(t => t.ThemeTemplates)
                .ThenInclude(tt => tt.ItemTemplate)
                    .ThenInclude(it => it!.Properties)
            .Include(t => t.ThemeCategories)
            .OrderBy(t => t.SortOrder)
            .ToListAsync();
    }

    public async Task<CollectionTheme?> GetByIdAsync(int id)
    {
        await using var context = await _contextFactory.CreateDbContextAsync();
        return await context.CollectionThemes
            .AsNoTracking()
            .Include(t => t.ThemeTemplates)
                .ThenInclude(tt => tt.ItemTemplate)
                    .ThenInclude(it => it!.Properties)
            .Include(t => t.ThemeCategories)
            .FirstOrDefaultAsync(t => t.Id == id);
    }
}
