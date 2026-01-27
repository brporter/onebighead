using backend.Data;
using backend.Models;
using Microsoft.EntityFrameworkCore;

namespace backend.Services;

/// <summary>
/// Seeds the database with initial system data like collection themes and item templates.
/// </summary>
public class DatabaseSeeder
{
    private readonly AppDbContext _context;

    public DatabaseSeeder(AppDbContext context)
    {
        _context = context;
    }

    public async Task SeedAsync()
    {
        await SeedItemTemplatesAsync();
        await SeedCollectionThemesAsync();
    }

    private async Task SeedItemTemplatesAsync()
    {
        // Check if system templates already exist
        if (await _context.ItemTemplates.AnyAsync(t => t.TenantId == null))
        {
            return;
        }

        var templates = new List<ItemTemplate>
        {
            // Book template
            new()
            {
                TenantId = null,
                Name = "Book",
                Description = "Template for cataloging books",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Author", SortOrder = 0 },
                    new() { Category = "Details", Name = "Publisher", SortOrder = 1 },
                    new() { Category = "Details", Name = "ISBN", SortOrder = 2 },
                    new() { Category = "Details", Name = "Publication Year", SortOrder = 3 },
                    new() { Category = "Details", Name = "Pages", SortOrder = 4 },
                    new() { Category = "Classification", Name = "Genre", SortOrder = 5 },
                    new() { Category = "Classification", Name = "Series", SortOrder = 6 },
                    new() { Category = "Physical", Name = "Format", SortOrder = 7 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 8 },
                }
            },
            // Video Game template
            new()
            {
                TenantId = null,
                Name = "Video Game",
                Description = "Template for cataloging video games",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Platform", SortOrder = 0 },
                    new() { Category = "Details", Name = "Developer", SortOrder = 1 },
                    new() { Category = "Details", Name = "Publisher", SortOrder = 2 },
                    new() { Category = "Details", Name = "Release Year", SortOrder = 3 },
                    new() { Category = "Classification", Name = "Genre", SortOrder = 4 },
                    new() { Category = "Classification", Name = "Rating", SortOrder = 5 },
                    new() { Category = "Details", Name = "Players", SortOrder = 6 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 7 },
                }
            },
            // Art & Collectibles template
            new()
            {
                TenantId = null,
                Name = "Art & Collectible",
                Description = "Template for cataloging art and collectibles",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Artist/Creator", SortOrder = 0 },
                    new() { Category = "Details", Name = "Medium", SortOrder = 1 },
                    new() { Category = "Details", Name = "Year", SortOrder = 2 },
                    new() { Category = "Physical", Name = "Dimensions", SortOrder = 3 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 4 },
                    new() { Category = "Provenance", Name = "Edition", SortOrder = 5 },
                    new() { Category = "Provenance", Name = "Authenticity", SortOrder = 6 },
                    new() { Category = "Value", Name = "Estimated Value", SortOrder = 7 },
                }
            },
            // Music/Records template
            new()
            {
                TenantId = null,
                Name = "Music Record",
                Description = "Template for cataloging music and vinyl records",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Artist", SortOrder = 0 },
                    new() { Category = "Details", Name = "Album", SortOrder = 1 },
                    new() { Category = "Details", Name = "Label", SortOrder = 2 },
                    new() { Category = "Details", Name = "Year", SortOrder = 3 },
                    new() { Category = "Classification", Name = "Genre", SortOrder = 4 },
                    new() { Category = "Physical", Name = "Format", SortOrder = 5 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 6 },
                    new() { Category = "Details", Name = "Catalog Number", SortOrder = 7 },
                }
            },
            // Coins & Stamps template
            new()
            {
                TenantId = null,
                Name = "Coin or Stamp",
                Description = "Template for cataloging coins and stamps",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Country", SortOrder = 0 },
                    new() { Category = "Details", Name = "Year", SortOrder = 1 },
                    new() { Category = "Details", Name = "Denomination", SortOrder = 2 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 3 },
                    new() { Category = "Classification", Name = "Rarity", SortOrder = 4 },
                    new() { Category = "Details", Name = "Mint/Printer", SortOrder = 5 },
                    new() { Category = "Value", Name = "Catalog Number", SortOrder = 6 },
                    new() { Category = "Value", Name = "Estimated Value", SortOrder = 7 },
                }
            },
            // General template
            new()
            {
                TenantId = null,
                Name = "General Item",
                Description = "Basic template for any type of collectible",
                Properties = new List<ItemTemplateProperty>
                {
                    new() { Category = "Details", Name = "Type", SortOrder = 0 },
                    new() { Category = "Details", Name = "Brand", SortOrder = 1 },
                    new() { Category = "Details", Name = "Model", SortOrder = 2 },
                    new() { Category = "Physical", Name = "Condition", SortOrder = 3 },
                    new() { Category = "Value", Name = "Estimated Value", SortOrder = 4 },
                }
            },
        };

        _context.ItemTemplates.AddRange(templates);
        await _context.SaveChangesAsync();
    }

    private async Task SeedCollectionThemesAsync()
    {
        // Check if themes already exist
        if (await _context.CollectionThemes.AnyAsync())
        {
            return;
        }

        // Get the system templates we just created
        var bookTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "Book");
        var gameTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "Video Game");
        var artTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "Art & Collectible");
        var musicTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "Music Record");
        var coinTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "Coin or Stamp");
        var generalTemplate = await _context.ItemTemplates.FirstOrDefaultAsync(t => t.TenantId == null && t.Name == "General Item");

        var themes = new List<CollectionTheme>
        {
            // Books theme
            new()
            {
                Name = "Books",
                Description = "Perfect for cataloging your book collection with fields for author, publisher, ISBN, and more.",
                IconName = "book",
                SortOrder = 0,
                ThemeTemplates = bookTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = bookTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "Fiction", SortOrder = 0 },
                    new() { Name = "Science Fiction", ParentName = "Fiction", SortOrder = 0 },
                    new() { Name = "Fantasy", ParentName = "Fiction", SortOrder = 1 },
                    new() { Name = "Mystery", ParentName = "Fiction", SortOrder = 2 },
                    new() { Name = "Romance", ParentName = "Fiction", SortOrder = 3 },
                    new() { Name = "Non-Fiction", SortOrder = 1 },
                    new() { Name = "Biography", ParentName = "Non-Fiction", SortOrder = 0 },
                    new() { Name = "History", ParentName = "Non-Fiction", SortOrder = 1 },
                    new() { Name = "Science", ParentName = "Non-Fiction", SortOrder = 2 },
                    new() { Name = "Self-Help", ParentName = "Non-Fiction", SortOrder = 3 },
                    new() { Name = "Reference", SortOrder = 2 },
                }
            },
            // Video Games theme
            new()
            {
                Name = "Video Games",
                Description = "Catalog your video game collection with fields for platform, developer, and genre.",
                IconName = "gamepad",
                SortOrder = 1,
                ThemeTemplates = gameTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = gameTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "By Platform", SortOrder = 0 },
                    new() { Name = "PlayStation", ParentName = "By Platform", SortOrder = 0 },
                    new() { Name = "Xbox", ParentName = "By Platform", SortOrder = 1 },
                    new() { Name = "Nintendo", ParentName = "By Platform", SortOrder = 2 },
                    new() { Name = "PC", ParentName = "By Platform", SortOrder = 3 },
                    new() { Name = "By Genre", SortOrder = 1 },
                    new() { Name = "Action", ParentName = "By Genre", SortOrder = 0 },
                    new() { Name = "RPG", ParentName = "By Genre", SortOrder = 1 },
                    new() { Name = "Strategy", ParentName = "By Genre", SortOrder = 2 },
                    new() { Name = "Sports", ParentName = "By Genre", SortOrder = 3 },
                }
            },
            // Art & Collectibles theme
            new()
            {
                Name = "Art & Collectibles",
                Description = "Track your art pieces and collectibles with fields for artist, medium, and provenance.",
                IconName = "palette",
                SortOrder = 2,
                ThemeTemplates = artTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = artTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "Paintings", SortOrder = 0 },
                    new() { Name = "Sculptures", SortOrder = 1 },
                    new() { Name = "Prints", SortOrder = 2 },
                    new() { Name = "Photography", SortOrder = 3 },
                    new() { Name = "Figurines", SortOrder = 4 },
                    new() { Name = "Other", SortOrder = 5 },
                }
            },
            // Music & Records theme
            new()
            {
                Name = "Music & Records",
                Description = "Organize your music collection with fields for artist, album, label, and format.",
                IconName = "music",
                SortOrder = 3,
                ThemeTemplates = musicTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = musicTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "By Format", SortOrder = 0 },
                    new() { Name = "Vinyl", ParentName = "By Format", SortOrder = 0 },
                    new() { Name = "CD", ParentName = "By Format", SortOrder = 1 },
                    new() { Name = "Cassette", ParentName = "By Format", SortOrder = 2 },
                    new() { Name = "By Genre", SortOrder = 1 },
                    new() { Name = "Rock", ParentName = "By Genre", SortOrder = 0 },
                    new() { Name = "Jazz", ParentName = "By Genre", SortOrder = 1 },
                    new() { Name = "Classical", ParentName = "By Genre", SortOrder = 2 },
                    new() { Name = "Electronic", ParentName = "By Genre", SortOrder = 3 },
                }
            },
            // Coins & Stamps theme
            new()
            {
                Name = "Coins & Stamps",
                Description = "Catalog your numismatic and philatelic collection with fields for country, year, and rarity.",
                IconName = "coin",
                SortOrder = 4,
                ThemeTemplates = coinTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = coinTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "Coins", SortOrder = 0 },
                    new() { Name = "US Coins", ParentName = "Coins", SortOrder = 0 },
                    new() { Name = "World Coins", ParentName = "Coins", SortOrder = 1 },
                    new() { Name = "Ancient Coins", ParentName = "Coins", SortOrder = 2 },
                    new() { Name = "Stamps", SortOrder = 1 },
                    new() { Name = "US Stamps", ParentName = "Stamps", SortOrder = 0 },
                    new() { Name = "World Stamps", ParentName = "Stamps", SortOrder = 1 },
                }
            },
            // General theme
            new()
            {
                Name = "General",
                Description = "A flexible starting point for any type of collection. Add your own categories and customize as needed.",
                IconName = "box",
                SortOrder = 5,
                ThemeTemplates = generalTemplate != null ? new List<CollectionThemeTemplate>
                {
                    new() { ItemTemplateId = generalTemplate.Id, SortOrder = 0 }
                } : new List<CollectionThemeTemplate>(),
                ThemeCategories = new List<CollectionThemeCategory>
                {
                    new() { Name = "Favorites", SortOrder = 0 },
                    new() { Name = "Wishlist", SortOrder = 1 },
                }
            },
        };

        _context.CollectionThemes.AddRange(themes);
        await _context.SaveChangesAsync();
    }
}
