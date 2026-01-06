using backend.Models;

namespace backend.Data;

public static class DatabaseSeeder
{
    public static void SeedDevelopmentData(AppDbContext context)
    {
        if (context.Categories.Any())
        {
            return; // Already seeded
        }

        var categories = new List<Category>
        {
            new() { Id = 1, TenantId = 1, Name = "Motorola 68000 Computers", Description = "Some Description", ParentCategoryId = null },
            new() { Id = 2, TenantId = 1, Name = "Compact Macintosh", Description = "Some description", ParentCategoryId = 1 },
            new() { Id = 3, TenantId = 1, Name = "Apple II", Description = "Some description", ParentCategoryId = 1 },
            new() { Id = 4, TenantId = 1, Name = "Peripherals", Description = "Some description", ParentCategoryId = null },
            new() { Id = 5, TenantId = 1, Name = "Monitors", Description = "Some description", ParentCategoryId = 4 },
            new() { Id = 6, TenantId = 1, Name = "Printers", Description = "Some description", ParentCategoryId = 4 },
            new() { Id = 7, TenantId = 1, Name = "Intel Computers", Description = "Some description", ParentCategoryId = null }
        };

        context.Categories.AddRange(categories);
        context.SaveChanges();
    }
}

