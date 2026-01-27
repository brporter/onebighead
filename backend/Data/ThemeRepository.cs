using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Data;

public class ThemeRepository : IThemeRepository
{
    private readonly AppDbContext _context;

    public ThemeRepository(AppDbContext context)
    {
        _context = context;
    }

    public async Task<IEnumerable<CollectionTheme>> GetAllAsync()
    {
        return await _context.CollectionThemes
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
        return await _context.CollectionThemes
            .AsNoTracking()
            .Include(t => t.ThemeTemplates)
                .ThenInclude(tt => tt.ItemTemplate)
                    .ThenInclude(it => it!.Properties)
            .Include(t => t.ThemeCategories)
            .FirstOrDefaultAsync(t => t.Id == id);
    }
}
