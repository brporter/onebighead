using backend.Models;

namespace backend.Data;

public static class DatabaseSeeder
{
    public static void SeedDevelopmentData(AppDbContext context)
    {
        // Seed default tenant first
        if (!context.Tenants.Any())
        {
            var defaultTenant = new Tenant
            {
                Id = 1,
                Name = "development.local",
                CreatedAt = DateTime.UtcNow
            };
            context.Tenants.Add(defaultTenant);
            context.SaveChanges();
        }

        // Seed default collection
        if (!context.Collections.Any())
        {
            var defaultCollection = new Collection
            {
                Id = 1,
                TenantId = 1,
                Name = "Vintage Macintosh Models",
                Description = "A collection of vintage Macintosh computers and peripherals",
                Slug = "vintage-macintosh-models",
                CreatedAt = DateTime.UtcNow
            };
            context.Collections.Add(defaultCollection);
            context.SaveChanges();
        }

        // Seed categories
        if (!context.Categories.Any())
        {
            var categories = new List<Category>
            {
                new() { Id = 1, TenantId = 1, CollectionId = 1, Name = "Unassigned Items", Description = "Items without a category", ParentCategoryId = null, IsSystem = true },
                new() { Id = 2, TenantId = 1, CollectionId = 1, Name = "Motorola 68000 Computers", Description = "Some Description", ParentCategoryId = null },
                new() { Id = 3, TenantId = 1, CollectionId = 1, Name = "Compact Macintosh", Description = "Some description", ParentCategoryId = 2 },
                new() { Id = 4, TenantId = 1, CollectionId = 1, Name = "Apple II", Description = "Some description", ParentCategoryId = 2 },
                new() { Id = 5, TenantId = 1, CollectionId = 1, Name = "Peripherals", Description = "Some description", ParentCategoryId = null },
                new() { Id = 6, TenantId = 1, CollectionId = 1, Name = "Monitors", Description = "Some description", ParentCategoryId = 5 },
                new() { Id = 7, TenantId = 1, CollectionId = 1, Name = "Printers", Description = "Some description", ParentCategoryId = 5 },
                new() { Id = 8, TenantId = 1, CollectionId = 1, Name = "Intel Computers", Description = "Some description", ParentCategoryId = null }
            };

            context.Categories.AddRange(categories);
            context.SaveChanges();
        }

        // Seed items
        if (!context.Items.Any())
        {
            var items = new List<Item>
            {
                new()
                {
                    Id = 1,
                    TenantId = 1,
                    CollectionId = 1,
                    CategoryId = 3,
                    Name = "Macintosh Plus",
                    Summary = "The Macintosh Plus is a personal computer designed, manufactured, and sold by Apple Computer, Inc. from January 16, 1986, to October 15, 1990.",
                    Description = "A description of this item that may be many sentences long and includes paragraphs, formatted with Markdown.",
                    Properties = new List<ItemProperty>
                    {
                        new("General", "Release Date", "02/01/1986"),
                        new("General", "Original Price", "$2999")
                    },
                    Images = new List<ItemImage>
                    {
                        new("https://upload.wikimedia.org/wikipedia/commons/thumb/5/5b/Apple_Macintosh_Plus_white_background_%28cropped%29.jpg/2560px-Apple_Macintosh_Plus_white_background_%28cropped%29.jpg", "Macintosh Plus front view"),
                        new("https://upload.wikimedia.org/wikipedia/commons/thumb/f/f5/Apple-Macintosh.jpg/1280px-Apple-Macintosh.jpg", "Macintosh Plus back view")
                    }
                },
                new()
                {
                    Id = 2,
                    TenantId = 1,
                    CollectionId = 1,
                    CategoryId = 3,
                    Name = "Macintosh Classic",
                    Summary = "The Macintosh Classic is a personal computer designed, manufactured, and sold by Apple Computer, Inc. from October 15, 1990, to September 15, 1992.",
                    Description = "A description of this item that may be many sentences long and includes paragraphs, formatted with Markdown.",
                    Properties = new List<ItemProperty>
                    {
                        new("General", "Release Date", "02/01/1988"),
                        new("General", "Original Price", "$2999"),
                        new("Hardware", "CPU", "Motorola 68030")
                    },
                    Images = new List<ItemImage>
                    {
                        new("https://upload.wikimedia.org/wikipedia/commons/d/d8/Macintosh_classic.jpg", "Macintosh Classic front view"),
                        new("https://upload.wikimedia.org/wikipedia/commons/3/37/Apple_Keyboard_II.jpg", "Macintosh Classic back view")
                    }
                }
            };

            context.Items.AddRange(items);
            context.SaveChanges();
        }
    }
}

