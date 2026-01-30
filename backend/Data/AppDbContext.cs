using System.Text.Json;
using backend.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;

namespace backend.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Category> Categories => Set<Category>();
    public DbSet<Collection> Collections => Set<Collection>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<User> Users => Set<User>();
    public DbSet<Item> Items => Set<Item>();
    public DbSet<PropertySuggestion> PropertySuggestions => Set<PropertySuggestion>();
    public DbSet<ItemTemplate> ItemTemplates => Set<ItemTemplate>();
    public DbSet<ItemTemplateProperty> ItemTemplateProperties => Set<ItemTemplateProperty>();
    public DbSet<CollectionItemTemplate> CollectionItemTemplates => Set<CollectionItemTemplate>();
    public DbSet<CategoryItemTemplate> CategoryItemTemplates => Set<CategoryItemTemplate>();
    public DbSet<StoredImage> StoredImages => Set<StoredImage>();
    public DbSet<CollectionTheme> CollectionThemes => Set<CollectionTheme>();
    public DbSet<CollectionThemeTemplate> CollectionThemeTemplates => Set<CollectionThemeTemplate>();
    public DbSet<CollectionThemeCategory> CollectionThemeCategories => Set<CollectionThemeCategory>();
    public DbSet<SupportRequest> SupportRequests => Set<SupportRequest>();
    public DbSet<SupportReply> SupportReplies => Set<SupportReply>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<Tenant>(entity =>
        {
            entity.HasKey(t => t.Id);
            entity.HasIndex(t => t.Name);
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(u => u.Id);
            
            entity.HasIndex(u => u.Email);
            entity.HasIndex(u => new { u.IdentityProvider, u.ProviderSubjectId }).IsUnique();

            entity.HasOne(u => u.Tenant)
                .WithMany(t => t.Users)
                .HasForeignKey(u => u.TenantId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Collection>(entity =>
        {
            entity.HasKey(c => c.Id);

            entity.HasOne(c => c.Tenant)
                .WithMany(t => t.Collections)
                .HasForeignKey(c => c.TenantId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(c => c.TenantId);
            entity.HasIndex(c => new { c.TenantId, c.Slug }).IsUnique();
        });

        modelBuilder.Entity<Category>(entity =>
        {
            entity.HasKey(c => c.Id);

            // Self-referencing FK must use Restrict/NoAction on SQL Server to avoid cycles
            entity.HasOne(c => c.ParentCategory)
                .WithMany(c => c.ChildCategories)
                .HasForeignKey(c => c.ParentCategoryId)
                .OnDelete(DeleteBehavior.Restrict);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            entity.HasOne(c => c.Tenant)
                .WithMany(t => t.Categories)
                .HasForeignKey(c => c.TenantId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(c => c.Collection)
                .WithMany(col => col.Categories)
                .HasForeignKey(c => c.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(c => c.TenantId);
            entity.HasIndex(c => c.CollectionId);
            entity.HasIndex(c => c.ParentCategoryId);
        });

        modelBuilder.Entity<Item>(entity =>
        {
            entity.HasKey(i => i.Id);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            entity.HasOne(i => i.Tenant)
                .WithMany()
                .HasForeignKey(i => i.TenantId)
                .OnDelete(DeleteBehavior.Restrict);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            // (Collections → Categories → Items via SetNull creates a second path)
            entity.HasOne(i => i.Collection)
                .WithMany(c => c.Items)
                .HasForeignKey(i => i.CollectionId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(i => i.Category)
                .WithMany()
                .HasForeignKey(i => i.CategoryId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(i => i.TenantId);
            entity.HasIndex(i => i.CollectionId);
            entity.HasIndex(i => i.CategoryId);

            // Index for user flag queries (finding items by Have/Want/Trade status)
            entity.HasIndex(i => i.UserFlag);
            // Composite index for tenant-scoped flag queries (most common use case)
            entity.HasIndex(i => new { i.TenantId, i.UserFlag });

            // Configure JSON columns for Properties and Images
            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            
            entity.Property(i => i.Properties)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<ItemProperty>>(v, jsonOptions) ?? new List<ItemProperty>()
                )
                .Metadata.SetValueComparer(new ValueComparer<List<ItemProperty>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c == null ? 0 : JsonSerializer.Serialize(c, jsonOptions).GetHashCode(),
                    c => JsonSerializer.Deserialize<List<ItemProperty>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)!
                ));

            entity.Property(i => i.Images)
                .HasConversion(
                    v => JsonSerializer.Serialize(v, jsonOptions),
                    v => JsonSerializer.Deserialize<List<ItemImage>>(v, jsonOptions) ?? new List<ItemImage>()
                )
                .Metadata.SetValueComparer(new ValueComparer<List<ItemImage>>(
                    (c1, c2) => JsonSerializer.Serialize(c1, jsonOptions) == JsonSerializer.Serialize(c2, jsonOptions),
                    c => c == null ? 0 : JsonSerializer.Serialize(c, jsonOptions).GetHashCode(),
                    c => JsonSerializer.Deserialize<List<ItemImage>>(JsonSerializer.Serialize(c, jsonOptions), jsonOptions)!
                ));
        });

        modelBuilder.Entity<PropertySuggestion>(entity =>
        {
            entity.HasKey(p => p.Id);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            entity.HasOne(p => p.Tenant)
                .WithMany()
                .HasForeignKey(p => p.TenantId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(p => p.Collection)
                .WithMany()
                .HasForeignKey(p => p.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(p => new { p.CollectionId, p.Type });
            entity.HasIndex(p => new { p.CollectionId, p.Type, p.Value }).IsUnique();
        });

        modelBuilder.Entity<ItemTemplate>(entity =>
        {
            entity.HasKey(t => t.Id);

            entity.HasOne(t => t.Tenant)
                .WithMany()
                .HasForeignKey(t => t.TenantId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(t => t.TenantId);
        });

        modelBuilder.Entity<ItemTemplateProperty>(entity =>
        {
            entity.HasKey(p => p.Id);

            entity.HasOne(p => p.ItemTemplate)
                .WithMany(t => t.Properties)
                .HasForeignKey(p => p.ItemTemplateId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(p => p.ItemTemplateId);
        });

        modelBuilder.Entity<CollectionItemTemplate>(entity =>
        {
            entity.HasKey(ct => new { ct.CollectionId, ct.ItemTemplateId });

            entity.HasOne(ct => ct.Collection)
                .WithMany(c => c.CollectionItemTemplates)
                .HasForeignKey(ct => ct.CollectionId)
                .OnDelete(DeleteBehavior.Cascade);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            entity.HasOne(ct => ct.ItemTemplate)
                .WithMany(t => t.CollectionItemTemplates)
                .HasForeignKey(ct => ct.ItemTemplateId)
                .OnDelete(DeleteBehavior.Restrict);
        });

        modelBuilder.Entity<CategoryItemTemplate>(entity =>
        {
            entity.HasKey(ct => new { ct.CategoryId, ct.ItemTemplateId });

            entity.HasOne(ct => ct.Category)
                .WithMany(c => c.CategoryItemTemplates)
                .HasForeignKey(ct => ct.CategoryId)
                .OnDelete(DeleteBehavior.Cascade);

            // Use Restrict to avoid multiple cascade paths in SQL Server
            entity.HasOne(ct => ct.ItemTemplate)
                .WithMany(t => t.CategoryItemTemplates)
                .HasForeignKey(ct => ct.ItemTemplateId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasIndex(ct => ct.CategoryId);
        });

        modelBuilder.Entity<StoredImage>(entity =>
        {
            entity.HasKey(s => s.Id);

            entity.HasOne(s => s.Tenant)
                .WithMany()
                .HasForeignKey(s => s.TenantId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(s => s.TenantId);
        });

        modelBuilder.Entity<CollectionTheme>(entity =>
        {
            entity.HasKey(t => t.Id);
            entity.HasIndex(t => t.SortOrder);
        });

        modelBuilder.Entity<CollectionThemeTemplate>(entity =>
        {
            entity.HasKey(tt => new { tt.ThemeId, tt.ItemTemplateId });

            entity.HasOne(tt => tt.Theme)
                .WithMany(t => t.ThemeTemplates)
                .HasForeignKey(tt => tt.ThemeId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(tt => tt.ItemTemplate)
                .WithMany()
                .HasForeignKey(tt => tt.ItemTemplateId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(tt => tt.ThemeId);
        });

        modelBuilder.Entity<CollectionThemeCategory>(entity =>
        {
            entity.HasKey(tc => tc.Id);

            entity.HasOne(tc => tc.Theme)
                .WithMany(t => t.ThemeCategories)
                .HasForeignKey(tc => tc.ThemeId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasIndex(tc => tc.ThemeId);
        });

        modelBuilder.Entity<SupportRequest>(entity =>
        {
            entity.HasKey(sr => sr.Id);

            entity.HasOne(sr => sr.User)
                .WithMany()
                .HasForeignKey(sr => sr.UserId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(sr => sr.UserId);
            entity.HasIndex(sr => sr.Email);
            entity.HasIndex(sr => sr.Status);
            entity.HasIndex(sr => sr.CreatedAt);
            entity.HasIndex(sr => sr.IsDeleted);
        });

        modelBuilder.Entity<SupportReply>(entity =>
        {
            entity.HasKey(r => r.Id);

            entity.HasOne(r => r.SupportRequest)
                .WithMany(sr => sr.Replies)
                .HasForeignKey(r => r.SupportRequestId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(r => r.User)
                .WithMany()
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.SetNull);

            entity.HasIndex(r => r.SupportRequestId);
            entity.HasIndex(r => new { r.SupportRequestId, r.IsFromAdmin, r.IsRead });
        });
    }
}

